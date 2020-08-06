#include "kbench-common.h"

extern void Hacl_Blake2b_32_blake2b_ccomp(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
);

void
blake2b_hacl_ccomp(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
)
{
  Hacl_Blake2b_32_blake2b_ccomp(nn, output, ll, d, kk, k);
}


