#include <stddef.h>
#include "crypto_hash.h"
#include "Hacl_SHA2_Scalar32.h"

extern void Hacl_SHA2_Scalar32_sha256(uint8_t *h, uint32_t len, uint8_t *b);

int crypto_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  Hacl_SHA2_Scalar32_sha256(out,inlen,in);
  return 0;
}
