#include "kbench-common.h"
#include <openssl/evp.h>

void blake2b_openssl(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k)
{

  EVP_MD_CTX *mdctx;
  mdctx = EVP_MD_CTX_new();

  EVP_DigestInit_ex(mdctx, EVP_blake2b512(), NULL);
  EVP_DigestUpdate(mdctx, d, ll);
  EVP_DigestFinal_ex(mdctx, output, &nn);
  EVP_MD_CTX_free(mdctx);
}
