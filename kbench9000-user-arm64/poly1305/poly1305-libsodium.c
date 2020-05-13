#include "kbench-common.h"
//#include <sodium.h>

extern int libsodium_crypto_onetimeauth(
   unsigned char *out,
   const unsigned char *in,
   unsigned long long inlen,
   const unsigned char *k);

void poly1305_libsodium(
  unsigned char *out,
  const unsigned char *in,
  unsigned long long inlen,
  const unsigned char *k
)
{
  libsodium_crypto_onetimeauth(out, in, inlen, k);
}
