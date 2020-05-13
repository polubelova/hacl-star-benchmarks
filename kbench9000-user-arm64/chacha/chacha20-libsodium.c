#include "kbench-common.h"
//#include <sodium.h>

extern int libsodium_crypto_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m,
                                       unsigned long long mlen,
                                       const unsigned char *n, uint32_t ic,
                                       const unsigned char *k);
void chacha20_libsodium(
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr
)
{
  libsodium_crypto_stream_chacha20_ietf_xor_ic(out, text, len, n1, ctr, key);
}
