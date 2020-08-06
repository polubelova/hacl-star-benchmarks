#include "kbench-common.h"

extern void Hacl_Blake2s_32_blake2s_ccomp(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
);

void
blake2s_hacl_ccomp(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
)
{
  Hacl_Blake2s_32_blake2s_ccomp(nn, output, ll, d, kk, k);
}


