#include "kbench-common.h"
#include "sha512-ossl.h"

extern int no_asm_SHA512_Init(SHA512_CTX *c);
extern int no_asm_SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
extern int no_asm_SHA512_Final(unsigned char *md, SHA512_CTX *c);

void sha512_lossl_no_asm(uint8_t* input, int len, uint8_t* hash){
  SHA512_CTX ctx;
  no_asm_SHA512_Init(&ctx);
  no_asm_SHA512_Update(&ctx,input,len);
  no_asm_SHA512_Final(hash,&ctx);
}
