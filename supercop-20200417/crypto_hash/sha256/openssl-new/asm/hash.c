#include <stddef.h>
#include "crypto_hash.h"

#include <sha.h>

int crypto_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx,in,inlen);
  SHA256_Final(out,&ctx);
  return 0;
}
