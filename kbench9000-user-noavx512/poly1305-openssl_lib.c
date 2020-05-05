#include "kbench-common.h"
#include "poly1305.h"

void poly1305_openssl_lib(uint8_t* mac, uint8_t* plain, int len, uint8_t* key){
  POLY1305 state;
  Poly1305_Init(&state,key);
  Poly1305_Update(&state,plain,len);
  Poly1305_Final(&state,mac);
}
