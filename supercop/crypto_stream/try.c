/*
 * crypto_stream/try.c version 20140423
 * D. J. Bernstein
 * Public domain.
 * Auto-generated by trygen.py; do not edit.
 */

#include "crypto_stream.h"
#include "try.h"

const char *primitiveimplementation = crypto_stream_IMPLEMENTATION;

#define TUNE_BYTES 16384
#ifdef SMALL
#define MAXTEST_BYTES 128
#else
#define MAXTEST_BYTES 4096
#endif
#ifdef SMALL
#define LOOPS 512
#else
#define LOOPS 4096
#endif

static unsigned char *k;
static unsigned char *n;
static unsigned char *m;
static unsigned char *c;
static unsigned char *s;
static unsigned char *k2;
static unsigned char *n2;
static unsigned char *m2;
static unsigned char *c2;
static unsigned char *s2;
#define klen crypto_stream_KEYBYTES
#define nlen crypto_stream_NONCEBYTES
unsigned long long mlen;
unsigned long long clen;
unsigned long long slen;

void preallocate(void)
{
}

void allocate(void)
{
  unsigned long long alloclen = 0;
  if (alloclen < TUNE_BYTES) alloclen = TUNE_BYTES;
  if (alloclen < MAXTEST_BYTES) alloclen = MAXTEST_BYTES;
  if (alloclen < crypto_stream_KEYBYTES) alloclen = crypto_stream_KEYBYTES;
  if (alloclen < crypto_stream_NONCEBYTES) alloclen = crypto_stream_NONCEBYTES;
  k = alignedcalloc(alloclen);
  n = alignedcalloc(alloclen);
  m = alignedcalloc(alloclen);
  c = alignedcalloc(alloclen);
  s = alignedcalloc(alloclen);
  k2 = alignedcalloc(alloclen);
  n2 = alignedcalloc(alloclen);
  m2 = alignedcalloc(alloclen);
  c2 = alignedcalloc(alloclen);
  s2 = alignedcalloc(alloclen);
}

void predoit(void)
{
}

void doit(void)
{
  crypto_stream_xor(c,m,TUNE_BYTES,n,k);
}

void test(void)
{
  unsigned long long j;
  unsigned long long loop;
  
  for (loop = 0;loop < LOOPS;++loop) {
    mlen = myrandom() % (MAXTEST_BYTES + 1);
    clen = mlen;
    slen = mlen;
    
    output_prepare(s2,s,slen);
    input_prepare(n2,n,nlen);
    input_prepare(k2,k,klen);
    if (crypto_stream(s,slen,n,k) != 0) fail("crypto_stream returns nonzero");
    checksum(s,slen);
    output_compare(s2,s,slen,"crypto_stream");
    input_compare(n2,n,nlen,"crypto_stream");
    input_compare(k2,k,klen,"crypto_stream");
    
    double_canary(s2,s,slen);
    double_canary(n2,n,nlen);
    double_canary(k2,k,klen);
    if (crypto_stream(s2,slen,n2,k2) != 0) fail("crypto_stream returns nonzero");
    if (memcmp(s2,s,slen) != 0) fail("crypto_stream is nondeterministic");
    
    output_prepare(c2,c,clen);
    input_prepare(m2,m,mlen);
    memcpy(n2,n,nlen);
    double_canary(n2,n,nlen);
    memcpy(k2,k,klen);
    double_canary(k2,k,klen);
    if (crypto_stream_xor(c,m,mlen,n,k) != 0) fail("crypto_stream_xor returns nonzero");
    
    for (j = 0;j < mlen;++j)
      if ((s[j] ^ m[j]) != c[j]) fail("crypto_stream_xor does not match crypto_stream");
    checksum(c,clen);
    output_compare(c2,c,clen,"crypto_stream_xor");
    input_compare(m2,m,mlen,"crypto_stream_xor");
    input_compare(n2,n,nlen,"crypto_stream_xor");
    input_compare(k2,k,klen,"crypto_stream_xor");
    
    double_canary(c2,c,clen);
    double_canary(m2,m,mlen);
    double_canary(n2,n,nlen);
    double_canary(k2,k,klen);
    if (crypto_stream_xor(c2,m2,mlen,n2,k2) != 0) fail("crypto_stream_xor returns nonzero");
    if (memcmp(c2,c,clen) != 0) fail("crypto_stream_xor is nondeterministic");
    
    double_canary(c2,c,clen);
    double_canary(m2,m,mlen);
    double_canary(n2,n,nlen);
    double_canary(k2,k,klen);
    if (crypto_stream_xor(m2,m2,mlen,n,k) != 0) fail("crypto_stream_xor with m=c overlap returns nonzero");
    if (memcmp(m2,c,clen) != 0) fail("crypto_stream_xor does not handle m=c overlap");
    memcpy(m2,m,mlen);
    if (crypto_stream_xor(n2,m,mlen,n2,k) != 0) fail("crypto_stream_xor with n=c overlap returns nonzero");
    if (memcmp(n2,c,clen) != 0) fail("crypto_stream_xor does not handle n=c overlap");
    memcpy(n2,n,nlen);
    if (crypto_stream_xor(k2,m,mlen,n,k2) != 0) fail("crypto_stream_xor with k=c overlap returns nonzero");
    if (memcmp(k2,c,clen) != 0) fail("crypto_stream_xor does not handle k=c overlap");
    memcpy(k2,k,klen);
  }
}
