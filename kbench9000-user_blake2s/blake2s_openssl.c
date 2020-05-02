// const EVP_MD *EVP_blake2s256(void);

 #include <stdio.h>
 #include <openssl/evp.h>

 void blake2s_openssl(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k)
{

	 EVP_MD_CTX *mdctx;
	 const EVP_MD *md;


	 unsigned char md_value[EVP_MAX_MD_SIZE];
	 int md_len, i;

	 md = EVP_blake2s256();

	 mdctx =  EVP_MD_CTX_new();

	 EVP_DigestInit_ex(mdctx, md, NULL);
	 EVP_DigestUpdate(mdctx, d, ll);
	 EVP_DigestFinal_ex(mdctx, output, &nn);
	 
	 EVP_MD_CTX_free(mdctx);
}

