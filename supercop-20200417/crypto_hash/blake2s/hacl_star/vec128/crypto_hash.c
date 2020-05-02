#include "crypto_hash.h"
#include "crypto_uint32.h"
#include <stddef.h>
#include <string.h>
#include "Hacl_Blake2s_128.h"

extern void Hacl_Blake2s_128_blake2s(uint32_t nn, uint8_t *output, uint32_t ll, uint8_t *d, uint32_t kk, uint8_t *k);
// Hacl_Blake2s_128_blake2s(exp_len,comp,in_len,in,key_len,key);


int crypto_hash(unsigned char *hash, const unsigned char *in, unsigned long long inlen) {
  Hacl_Blake2s_128_blake2s(32, hash, inlen, in, 0, NULL);
  return 0;
}
