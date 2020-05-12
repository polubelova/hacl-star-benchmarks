#include "kbench-common.h"

extern void no_asm_ChaCha20_ctr32(
   unsigned char *cipher,
   unsigned char *plain,
   unsigned long long len,
   unsigned char *key,
   unsigned char *nonce);

void chacha20_openssl_c(
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr)
{
  unsigned char nonce[16] = {0};
  store32_le(nonce, ctr);
  memcpy(nonce+4, n1, 12);  
  no_asm_ChaCha20_ctr32(out, text, len, key, nonce);
}
