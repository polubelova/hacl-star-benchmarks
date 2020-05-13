#include "kbench-common.h"
#include "sha256-openssl.h"

extern int no_asm_SHA256_Init(SHA256_CTX *c);
extern int no_asm_SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
extern int no_asm_SHA256_Final(unsigned char *md, SHA256_CTX *c);

void sha256_openssl_c(uint8_t* input, int len, uint8_t* hash){
  SHA256_CTX ctx;
  no_asm_SHA256_Init(&ctx);
  no_asm_SHA256_Update(&ctx,input,len);
  no_asm_SHA256_Final(hash,&ctx);
}
