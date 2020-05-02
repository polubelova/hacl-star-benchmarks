#include <stddef.h>
#include "crypto_hash.h"
#include "Hacl_SHA2_Vec512.h"

extern void
Hacl_SHA2_Vec512_sha512_8(
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
  uint8_t r1[64] = {0};
  uint8_t r2[64] = {0};
  uint8_t r3[64] = {0};
  uint8_t r4[64] = {0};
  uint8_t r5[64] = {0};
  uint8_t r6[64] = {0};
  uint8_t r7[64] = {0};

  Hacl_SHA2_Vec512_sha512_8(out,r1,r2,r3,r4,r5,r6,r7,inlen,in,in,in,in,in,in,in,in);
  return 0;
}
