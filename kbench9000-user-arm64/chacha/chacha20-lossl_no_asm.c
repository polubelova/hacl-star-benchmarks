#include "kbench-common.h"

extern void no_asm_ChaCha20_ctr32(
   unsigned char *cipher,
   unsigned char *plain,
   unsigned long long len,
   unsigned char *key,
   unsigned char *nonce);

void chacha20_lossl_no_asm(
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr)
{
  unsigned int ivp[4] = {0};
  ivp[0] = ctr;
  ivp[1] = 10;
  memcpy(ivp + 1, n1, sizeof(int) * 3);
  no_asm_ChaCha20_ctr32(out, text, len, key, ivp);
}
