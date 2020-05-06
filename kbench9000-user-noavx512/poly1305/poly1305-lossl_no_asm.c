#include "kbench-common.h"
#include "poly1305_ossl.h"

extern void no_asm_Poly1305_Init(POLY1305 *ctx, const unsigned char key[32]);
extern void no_asm_Poly1305_Update(POLY1305 *ctx, const unsigned char *inp, size_t len);
extern void no_asm_Poly1305_Final(POLY1305 *ctx, unsigned char mac[16]);

void poly1305_lossl_no_asm(uint8_t* mac, uint8_t* plain, int len, uint8_t* key){
  POLY1305 state;
  no_asm_Poly1305_Init(&state,key);
  no_asm_Poly1305_Update(&state,plain,len);
  no_asm_Poly1305_Final(&state,mac);
}
