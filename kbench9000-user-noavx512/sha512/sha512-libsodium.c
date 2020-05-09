#include "kbench-common.h"
//#include <sodium.h>

extern int libsodium_crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                   unsigned long long inlen);

void sha512_libsodium(uint8_t *input, uint32_t input_len, uint8_t *dst)
{
  libsodium_crypto_hash_sha512(dst, input, input_len);
}
