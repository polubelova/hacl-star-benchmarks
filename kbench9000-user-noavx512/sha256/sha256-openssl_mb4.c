#include "kbench-common.h"
#include "hash_simd.h"

extern void sha256_4way_simd(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]);

int sha256_openssl_mb4(uint8_t *in, uint32_t inlen, uint8_t *out){
  uint8_t r1[32] = {0};
  uint8_t r2[32] = {0};
  uint8_t r3[32] = {0};

  uint8_t *hash_inp[4];
  hash_inp[0] = in;
  hash_inp[1] = in;
  hash_inp[2] = in;
  hash_inp[3] = in;

  uint8_t *H4[4];
  H4[0] = out;
  H4[1] = r1;
  H4[2] = r2;
  H4[3] = r3;

  sha256_4way_simd(hash_inp, inlen, H4);
  return 0;
}
