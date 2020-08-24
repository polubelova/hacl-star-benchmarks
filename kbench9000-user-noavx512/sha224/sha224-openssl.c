#include "kbench-common.h"
#include "sha224-openssl.h"


void sha224_openssl(uint8_t* input, int len, uint8_t* hash){
  SHA256_CTX ctx;
  SHA224_Init(&ctx);
  SHA224_Update(&ctx,input,len);
  SHA224_Final(hash,&ctx);
}
