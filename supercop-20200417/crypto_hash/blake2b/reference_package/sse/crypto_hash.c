#include "crypto_hash.h"
#include "crypto_uint64.h"
#include <stddef.h>
#include <string.h>


int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen) {
  return blake2b( out, 64, in, inlen, NULL, 0 );
}
