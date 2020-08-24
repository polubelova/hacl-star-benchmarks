#include "kbench-common.h"
#include "sha384-openssl.h"


void sha384_openssl(uint8_t* input, int len, uint8_t* hash){
  SHA512_CTX ctx;
  SHA384_Init(&ctx);
  SHA384_Update(&ctx,input,len);
  SHA384_Final(hash,&ctx);
}
