#include "kbench-common.h"

extern void chacha20_avx2(
  unsigned char *out,
  const unsigned char *in,
  unsigned long long inlen,
  const unsigned char *k,
  const unsigned char *n,
  unsigned int counter);

void chacha20_jazz256(
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr
)
{
  chacha20_avx2(out, text, len, key, n1, ctr);
}
