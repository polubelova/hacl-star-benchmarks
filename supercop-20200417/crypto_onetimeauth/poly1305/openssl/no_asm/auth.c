#include "crypto_onetimeauth.h"
#include <stddef.h>

#include "poly1305.h"

int crypto_onetimeauth(
  unsigned char *out,
  const unsigned char *in,
  unsigned long long inlen,
  const unsigned char *k
)
{
  POLY1305 state;
  Poly1305_Init(&state,k);
  Poly1305_Update(&state,in,inlen);
  Poly1305_Final(&state,out);
  return 0;
}
