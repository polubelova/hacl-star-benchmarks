#include "kbench-common.h"
#include "sha224-openssl.h"

extern int no_asm_SHA224_Init(SHA256_CTX *c);
extern int no_asm_SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
extern int no_asm_SHA224_Final(unsigned char *md, SHA256_CTX *c);

void sha224_openssl_c(uint8_t* input, int len, uint8_t* hash){
  SHA256_CTX ctx;
  no_asm_SHA224_Init(&ctx);
  no_asm_SHA224_Update(&ctx,input,len);
  no_asm_SHA224_Final(hash,&ctx);
}
