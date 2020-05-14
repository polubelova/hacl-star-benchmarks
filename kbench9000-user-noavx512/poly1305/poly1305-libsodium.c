#include "kbench-common.h"
//#include <sodium.h>

extern int sodium_init(void);
extern int crypto_onetimeauth(
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
  if (sodium_init() == -1) {
    return;
  }  
  crypto_onetimeauth(out, in, inlen, k);
}
