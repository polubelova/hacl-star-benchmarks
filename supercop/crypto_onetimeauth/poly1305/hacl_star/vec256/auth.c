#include "crypto_onetimeauth.h"
#include "Hacl_Poly1305_256.h"

int crypto_onetimeauth(
  unsigned char *out,
  const unsigned char *in,
  unsigned long long inlen,
  const unsigned char *k
)
{
  Hacl_Poly1305_256_poly1305_mac(out, inlen, in, k);
  return 0;
}
