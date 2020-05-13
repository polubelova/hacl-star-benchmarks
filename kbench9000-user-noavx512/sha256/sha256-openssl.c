#include "kbench-common.h"
#include "sha256-openssl.h"


void sha256_openssl(uint8_t* input, int len, uint8_t* hash){
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx,input,len);
  SHA256_Final(hash,&ctx);
}
