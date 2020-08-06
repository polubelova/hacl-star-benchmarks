#include "kbench-common.h"

extern void Hacl_SHA2_Scalar32_sha256_ccomp(uint8_t *h, uint32_t len, uint8_t *b);

void sha256_hacl_ccomp(uint8_t *input, uint32_t input_len, uint8_t *dst)
{
  Hacl_SHA2_Scalar32_sha256_ccomp(dst, input_len, input);
}
