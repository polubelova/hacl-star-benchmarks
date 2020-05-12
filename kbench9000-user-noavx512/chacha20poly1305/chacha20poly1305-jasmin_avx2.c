#include "kbench-common.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#if 0
...

   Some protocols may have unique per-invocation inputs that are not 96
   bits in length.  For example, IPsec may specify a 64-bit nonce.  In
   such a case, it is up to the protocol document to define how to
   transform the protocol nonce into a 96-bit nonce, for example, by
   concatenating a constant value.

...

  poly1305_key_gen(key,nonce):
    counter = 0
    block = chacha20_block(key,counter,nonce)
    return block[0..31]
    end

...

   o  K_LEN (key length) is 32 octets.

   o  P_MAX (maximum size of the plaintext) is 274,877,906,880 bytes, or
      nearly 256 GB.

   o  A_MAX (maximum size of the associated data) is set to 2^64-1
      octets by the length field for associated data.

   o  N_MIN = N_MAX = 12 octets.

   o  C_MAX = P_MAX + tag length = 274,877,906,896 octets.

...

  chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
     nonce = constant | iv
     otk = poly1305_key_gen(key, nonce)
     ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
     mac_data = aad | pad16(aad)
     mac_data |= ciphertext | pad16(ciphertext)
     mac_data |= num_to_8_le_bytes(aad.length)
     mac_data |= num_to_8_le_bytes(ciphertext.length)
     tag = poly1305_mac(mac_data, otk)
     return (ciphertext, tag)

#endif

extern void libjc_avx2_chacha20_avx2(uint8_t*, uint8_t*, uint64_t, uint8_t*, uint8_t*, uint64_t);
extern void libjc_avx2_poly1305_avx2(uint8_t*, uint8_t*, uint64_t, uint8_t*);

// @pre otk[64] key[32] nonce[12]
static inline
void poly1305_key_gen(
  uint8_t *otk,
  uint8_t *key,
  uint8_t *nonce)
{
  memset(otk, 0, 32);
  libjc_avx2_chacha20_avx2(otk, otk, 64, key, nonce, 0);
  memset(otk+32, 0, 32);
}

static inline
void chacha20_encrypt(
  uint8_t *ciphertext,
  uint8_t *key,
  uint64_t counter,
  uint8_t *nonce,
  uint8_t *plaintext,
  uint64_t plaintext_len)
{
  libjc_avx2_chacha20_avx2(ciphertext, plaintext, plaintext_len, key, nonce, counter);
}

static inline
void poly1305_mac(uint8_t *tag, uint8_t *mac_data, uint64_t mac_data_len, uint8_t *otk)
{
  libjc_avx2_poly1305_avx2(tag, mac_data, mac_data_len, otk);
}

static inline
void num_to_8_le_bytes(uint8_t *d, uint64_t n)
{
  int i;
  for(i=0;i<8;i++)
  { d[i] = n & 0xFF; n >>= 8; }
}

void chacha20_aead_encrypt(
  uint8_t *ciphertext, uint8_t *tag,
  uint8_t *aad, uint64_t aad_len,
  uint8_t *key,
  uint8_t *iv, uint64_t iv_len,
  uint8_t *constant, uint64_t constant_len,
  uint8_t *plaintext, uint64_t plaintext_len)
{
  #define align16(x) ((x+15)&~0xF)

  uint8_t nonce[12];
  uint8_t otk[64];
  uint64_t mac_data_len = align16(aad_len) + align16(plaintext_len) + 16/*lengths*/;
  #ifdef MALLOC
  uint8_t *mac_data = (uint8_t*) malloc(mac_data_len*sizeof(uint8_t));
  #else
  uint8_t mac_data[mac_data_len];
  #endif
  uint8_t *mac_data_p;

  mac_data_p = &(mac_data[0]);

  /* nonce = constant | iv */
  memcpy(nonce, constant, constant_len);
  memcpy(nonce+constant_len, iv, iv_len);

  /* otk = poly1305_key_gen(key, nonce) */
  poly1305_key_gen(otk, key, nonce);

  /* ciphertext = chacha20_encrypt(key, 1, nonce, plaintext) */
  chacha20_encrypt(ciphertext, key, 1, nonce, plaintext, plaintext_len);

  /* mac_data = aad | pad16(aad) */
  memcpy(mac_data, aad, aad_len);
  memset(mac_data+aad_len, 0, align16(aad_len)-aad_len);
  mac_data_p += align16(aad_len);

  /* mac_data |= ciphertext | pad16(ciphertext) */
  memcpy(mac_data_p, ciphertext, plaintext_len);
  memset(mac_data_p+plaintext_len, 0, align16(plaintext_len)-plaintext_len);
  mac_data_p += align16(plaintext_len);

  /* mac_data |= num_to_8_le_bytes(aad.length) */
  num_to_8_le_bytes(mac_data_p, aad_len);
  mac_data_p += 8;

  /* mac_data |= num_to_8_le_bytes(ciphertext.length) */
  num_to_8_le_bytes(mac_data_p, plaintext_len);

  poly1305_mac(tag, mac_data, mac_data_len, otk);

  #ifdef MALLOC
  free(mac_data);
  #endif

  #undef MALLOC
  #undef align16
}

void chacha20poly1305_jasmin_avx2(u32 mlen, u8 *c, u8 *tag, u8 *m, u8 *ad, u32 adlen, u8 *n, u8 *k){
  /* nonce = constant | iv */
  chacha20_aead_encrypt(c,tag,ad,adlen,k,n,12,NULL,0,m,mlen);
}
