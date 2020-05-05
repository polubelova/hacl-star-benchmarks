#include "chacha.h"
#include "kbench-common.h"
//#include <openssl/evp.h>
void chacha20_openssl_lib(
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr
)
{
   /*  unsigned int ivp[4] = {0}; */
   /*  ivp[0] = ctr; */
   /*  ivp[1] = 10; */
   /*  memcpy(ivp + 1, n1, sizeof(int) * 3); */
  
   /* EVP_CIPHER_CTX *ctx; */
   /* int clen; */
   /* ctx = EVP_CIPHER_CTX_new(); */
   /* EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, ivp); */
   /* EVP_EncryptUpdate(ctx, out, &clen, text, len); */
   /* EVP_EncryptFinal_ex(ctx, out + clen, &clen); */
   /* EVP_CIPHER_CTX_free(ctx); */
  
    unsigned int ivp[4] = {0};
    ivp[0] = ctr;
    ivp[1] = 10;
    memcpy(ivp + 1, n1, sizeof(int) * 3);
    ChaCha20_ctr32(out, text,
        len, key,
        ivp);
}
