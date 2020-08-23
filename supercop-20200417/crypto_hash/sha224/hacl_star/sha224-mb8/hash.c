#include <stddef.h>
#include "crypto_hash.h"
#include "Hacl_SHA2_Vec256.h"

extern void Hacl_SHA2_Vec256_sha224_8(
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
  uint8_t r1[28] = {0};
  uint8_t r2[28] = {0};
  uint8_t r3[28] = {0};
  uint8_t r4[28] = {0};
  uint8_t r5[28] = {0};
  uint8_t r6[28] = {0};  
  uint8_t r7[28] = {0};
  Hacl_SHA2_Vec256_sha224_8(out,r1,r2,r3,r4,r5,r6,r7,inlen,in,in,in,in,in,in,in,in);
  return 0;
}
