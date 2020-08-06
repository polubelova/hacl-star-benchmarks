#include "kbench-common.h"

extern void Hacl_SHA2_Scalar32_sha512_ccomp(uint8_t *h, uint32_t len, uint8_t *b);

void sha512_hacl_ccomp(uint8_t *input, uint32_t input_len, uint8_t *dst)
{
  Hacl_SHA2_Scalar32_sha512_ccomp(dst, input_len, input);
}
