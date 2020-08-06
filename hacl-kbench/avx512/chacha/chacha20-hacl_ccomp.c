#include "kbench-common.h"

extern void Hacl_Chacha20_Vec32_chacha20_encrypt_32_ccomp(
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr
);

void chacha20_hacl_ccomp(
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr
)
{
  Hacl_Chacha20_Vec32_chacha20_encrypt_32_ccomp(len, out, text, key, n1, ctr);
}
