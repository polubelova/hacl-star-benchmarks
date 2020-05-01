#include <sodium.h>

void
blake2b_nacl(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
)
{
	crypto_generichash(output, nn,
                   d, ll,
                   k, kk);
}