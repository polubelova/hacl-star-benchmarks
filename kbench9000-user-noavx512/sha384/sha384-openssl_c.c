#include "kbench-common.h"
#include "sha384-openssl.h"

extern int no_asm_SHA384_Init(SHA512_CTX *c);
extern int no_asm_SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
extern int no_asm_SHA384_Final(unsigned char *md, SHA512_CTX *c);

void sha384_openssl_c(uint8_t* input, int len, uint8_t* hash){
  SHA512_CTX ctx;
  no_asm_SHA384_Init(&ctx);
  no_asm_SHA384_Update(&ctx,input,len);
  no_asm_SHA384_Final(hash,&ctx);
}
