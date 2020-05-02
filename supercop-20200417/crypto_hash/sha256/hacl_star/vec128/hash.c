#include <stddef.h>
#include "crypto_hash.h"
#include "Hacl_SHA2_Vec128.h"

extern void Hacl_SHA2_Vec128_sha256_4(
  uint8_t *r0,
  uint8_t *r1,
  uint8_t *r2,
  uint8_t *r3,
  uint32_t len,
  uint8_t *b0,
  uint8_t *b1,
  uint8_t *b2,
  uint8_t *b3
);

int crypto_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  uint8_t r1[32] = {0};
  uint8_t r2[32] = {0};
  uint8_t r3[32] = {0};
  Hacl_SHA2_Vec128_sha256_4(out,r1,r2,r3,inlen,in,in,in,in);
  return 0;
}
