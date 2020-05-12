#include "kbench-common.h"
#include "sha512-openssl.h"


void sha512_openssl(uint8_t* input, int len, uint8_t* hash){
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx,input,len);
  SHA512_Final(hash,&ctx);
}
