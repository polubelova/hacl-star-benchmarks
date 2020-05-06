#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <openssl/sha.h>


void sha512_openssl(uint8_t* input, int len, uint8_t* hash){
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx,input,len);
  SHA512_Final(hash,&ctx);
}

