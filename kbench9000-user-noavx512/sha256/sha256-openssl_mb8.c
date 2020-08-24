#include "kbench-common.h"
#include "hash_simd.h"


extern void sha256_8way_simd(uint8_t *input[8], uint16_t input_len, uint8_t *digest[8]);

int sha256_openssl_mb8(uint8_t *in, uint32_t inlen, uint8_t *out)
{
  uint8_t r1[32] = {0};
  uint8_t r2[32] = {0};
  uint8_t r3[32] = {0};
  uint8_t r4[32] = {0};
  uint8_t r5[32] = {0};
  uint8_t r6[32] = {0};
  uint8_t r7[32] = {0};

  uint8_t *hash_inp[8];
  hash_inp[0] = in;
  hash_inp[1] = in;
  hash_inp[2] = in;
  hash_inp[3] = in;
  hash_inp[4] = in;
  hash_inp[5] = in;
  hash_inp[6] = in;
  hash_inp[7] = in;

  uint8_t *H8[8];
  H8[0] = out;
  H8[1] = r1;
  H8[2] = r2;
  H8[3] = r3;
  H8[4] = r4;
  H8[5] = r5;
  H8[6] = r6;
  H8[7] = r7;

  sha256_8way_simd(hash_inp, inlen, H8);
  return 0;
}
