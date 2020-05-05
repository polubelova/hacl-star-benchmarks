#include <sodium.h>

void chacha20_libsodium(
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr
)
{
  crypto_stream_chacha20_ietf_xor_ic(out, text, len, n1, ctr, key);
}