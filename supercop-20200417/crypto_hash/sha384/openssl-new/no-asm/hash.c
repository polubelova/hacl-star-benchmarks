#include <stddef.h>
#include "crypto_hash.h"
#include <sha.h>

int crypto_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  SHA512_CTX ctx;
  SHA384_Init(&ctx);
  SHA384_Update(&ctx,in,inlen);
  SHA384_Final(out,&ctx);
  return 0;
}
