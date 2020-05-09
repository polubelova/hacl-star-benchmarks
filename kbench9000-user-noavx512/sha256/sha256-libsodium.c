#include "kbench-common.h"
//#include <sodium.h>

extern int crypto_hash_sha256(unsigned char *out, const unsigned char *in,
                   unsigned long long inlen);

void sha256_libsodium(uint8_t *input, uint32_t input_len, uint8_t *dst)
{
  crypto_hash_sha256(dst, input, input_len);
}
