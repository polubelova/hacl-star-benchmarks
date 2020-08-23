#include <stddef.h>
#include "crypto_hash.h"
#include "Hacl_SHA2_Vec512.h"

extern void
Hacl_SHA2_Vec512_sha384_8(
  uint8_t *r0,
  uint8_t *r1,
  uint8_t *r2,
  uint8_t *r3,
  uint8_t *r4,
  uint8_t *r5,
  uint8_t *r6,
  uint8_t *r7,
  uint32_t len,
  uint8_t *b0,
  uint8_t *b1,
  uint8_t *b2,
  uint8_t *b3,
  uint8_t *b4,
  uint8_t *b5,
  uint8_t *b6,
  uint8_t *b7
);


int crypto_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  uint8_t r1[48] = {0};
  uint8_t r2[48] = {0};
  uint8_t r3[48] = {0};
  uint8_t r4[48] = {0};
  uint8_t r5[48] = {0};
  uint8_t r6[48] = {0};
  uint8_t r7[48] = {0};

  Hacl_SHA2_Vec512_sha384_8(out,r1,r2,r3,r4,r5,r6,r7,inlen,in,in,in,in,in,in,in,in);
  return 0;
}
