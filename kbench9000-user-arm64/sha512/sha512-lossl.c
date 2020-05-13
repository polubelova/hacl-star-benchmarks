#include "kbench-common.h"
#include "sha512-ossl.h"


void sha512_lossl(uint8_t* input, int len, uint8_t* hash){
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx,input,len);
  SHA512_Final(hash,&ctx);
}
