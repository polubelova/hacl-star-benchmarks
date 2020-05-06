#include "kbench-common.h"

extern void poly1305_avx2(
  unsigned char *out,
  const unsigned char *in,
  unsigned long long inlen,
  const unsigned char *k
);

void poly1305_jazz256(
  unsigned char *out,
  const unsigned char *in,
  unsigned long long inlen,
  const unsigned char *k
)
{
  poly1305_avx2(out, in, inlen, k);
}
