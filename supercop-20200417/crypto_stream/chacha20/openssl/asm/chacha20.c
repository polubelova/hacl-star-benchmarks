#include "crypto_stream.h"
#include <string.h>

extern void ChaCha20_ctr32(unsigned char *cipher, unsigned char *plain, unsigned long long len, unsigned char *key, unsigned char *nonce);

int crypto_stream(
  unsigned char *out,
  unsigned long long outlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  unsigned char nonce[16];
  memset(out, 0, outlen);
  memset(nonce, 0, 8);
  memcpy(nonce+8, n, 8);
  ChaCha20_ctr32(out, out, outlen, k, nonce);
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
  unsigned char nonce[16];
  memset(nonce, 0, 8);
  memcpy(nonce+8, n, 8);
  ChaCha20_ctr32(out, in, inlen, k, nonce);
  return 0;
}
