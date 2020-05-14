#include "kbench-common.h"
//#include <sodium.h>

extern int libsodium_sodium_init(void);
extern int libsodium_crypto_generichash(unsigned char *out, size_t outlen,
                       const unsigned char *in, unsigned long long inlen,
                       const unsigned char *key, size_t keylen);


void
blake2b_libsodium(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
)
{
  if (libsodium_sodium_init() == -1) {
    return;
  }  
  libsodium_crypto_generichash(output, nn, d, ll, k, kk);
}
