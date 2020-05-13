#include "kbench-common.h"
#include <openssl/evp.h>

int chacha20poly1305_lossl(u32 mlen, u8 *c, u8 *tag, u8 *m, u8 *ad, u32 adlen, u8 *n, u8 *k){
  EVP_CIPHER_CTX *x;
  x = EVP_CIPHER_CTX_new();
  int outlen = 0;
  int ok = 1;

  //EVP_CIPHER_CTX_init(x);
  if (ok == 1) ok = EVP_EncryptInit_ex(x,EVP_chacha20_poly1305(),0,0,0);
  if (ok == 1) ok = EVP_CIPHER_CTX_ctrl(x,EVP_CTRL_AEAD_SET_IVLEN,12,0);
  if (ok == 1) ok = EVP_EncryptInit_ex(x,0,0,k,n);
  if (ok == 1) ok = EVP_EncryptUpdate(x,0,&outlen,ad,adlen);
  if (ok == 1) ok = EVP_EncryptUpdate(x,c,&outlen,m,mlen);
  if (ok == 1) ok = EVP_EncryptFinal_ex(x,c,&outlen);
  if (ok == 1) ok = EVP_CIPHER_CTX_ctrl(x,EVP_CTRL_AEAD_GET_TAG,16,tag);
  EVP_CIPHER_CTX_cleanup(x);
  return ok;
}
