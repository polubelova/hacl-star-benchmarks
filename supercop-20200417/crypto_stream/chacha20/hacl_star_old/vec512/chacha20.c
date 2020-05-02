#include "crypto_stream.h"
#include <string.h>
#include "Hacl_Chacha20_Vec512.h"

int crypto_stream(
  unsigned char *out,
  unsigned long long outlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  unsigned char nonce[12];
  memset(out, 0, outlen);
  memset(nonce, 0, 4);
  memcpy(nonce + 4, n, 8);
  Hacl_Chacha20_Vec512_chacha20_encrypt_512(outlen, out, out, k, nonce, 0);
  return 0;
}

int crypto_stream_xor(
  unsigned char *out,
  const unsigned char *in,
  unsigned long long inlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  unsigned char nonce[12];
  memset(nonce, 0, 4);
  memcpy(nonce + 4, n, 8);
  Hacl_Chacha20_Vec512_chacha20_encrypt_512(inlen, out, in, k, nonce, 0);
  return 0;
}
