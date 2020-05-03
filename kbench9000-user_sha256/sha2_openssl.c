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


void sha2_openssl(uint8_t* input, int len, uint8_t* hash){
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx,input,len);
  SHA256_Final(hash,&ctx);
}

