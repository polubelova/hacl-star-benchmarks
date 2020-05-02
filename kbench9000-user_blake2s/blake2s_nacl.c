#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// #include "common.h"


#include <stdint.h>
#include <stdlib.h>


// https://github.com/jedisct1/hashseq/tree/master/blake2s
// https://github.com/jedisct1/libsodium/issues/788

#ifndef NATIVE_BIG_ENDIAN
# ifndef NATIVE_LITTLE_ENDIAN
#  define NATIVE_LITTLE_ENDIAN
# endif
#endif

#define ROTR32(X, B) (uint32_t)(((X) >> (B)) | ((X) << (32 - (B))))

#define LOAD32_LE(SRC) load32_le(SRC)
static inline uint32_t
load32_le(const uint8_t src[4])
{
#ifdef NATIVE_LITTLE_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[0];
    w |= (uint32_t) src[1] << 8;
    w |= (uint32_t) src[2] << 16;
    w |= (uint32_t) src[3] << 24;
    return w;
#endif
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void
store32_le(uint8_t dst[4], uint32_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[3] = (uint8_t) w;
#endif
}

#define G(A, B, C, D)                \
    do {                             \
        (A) += (B);                  \
        (D) = ROTR32((D) ^ (A), 16); \
        (C) += (D);                  \
        (B) = ROTR32((B) ^ (C), 12); \
        (A) += (B);                  \
        (D) = ROTR32((D) ^ (A), 8);  \
        (C) += (D);                  \
        (B) = ROTR32((B) ^ (C), 7);  \
    } while (0)

static const uint32_t IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint8_t BLAKE2S_SIGMA[10][8] = {
    { 1, 35, 69, 103, 137, 171, 205, 239 },
    { 234, 72, 159, 214, 28, 2, 183, 83 },
    { 184, 192, 82, 253, 174, 54, 113, 148 },
    { 121, 49, 220, 190, 38, 90, 64, 248 },
    { 144, 87, 36, 175, 225, 188, 104, 61 },
    { 44, 106, 11, 131, 77, 117, 254, 25 },
    { 197, 31, 237, 74, 7, 99, 146, 139 },
    { 219, 126, 193, 57, 80, 244, 134, 42 },
    { 111, 233, 179, 8, 194, 215, 20, 165 },
    { 162, 132, 118, 21, 251, 158, 60, 208 }
};

#define BLAKE2S_G(M, R, I, A, B, C, D)         \
    do {                                       \
        const uint8_t x = BLAKE2S_SIGMA[R][I]; \
        (A) += (B) + (M)[(x >> 4) & 0xf];      \
        (D) = ROTR32((D) ^ (A), 16);           \
        (C) += (D);                            \
        (B) = ROTR32((B) ^ (C), 12);           \
        (A) += (B) + (M)[x & 0xf];             \
        (D) = ROTR32((D) ^ (A), 8);            \
        (C) += (D);                            \
        (B) = ROTR32((B) ^ (C), 7);            \
    } while (0)

static inline void
blake2s_round(uint32_t state[16], const uint32_t mb32[16], int round)
{
    BLAKE2S_G(mb32, round, 0, state[0], state[4], state[8], state[12]);
    BLAKE2S_G(mb32, round, 1, state[1], state[5], state[9], state[13]);
    BLAKE2S_G(mb32, round, 2, state[2], state[6], state[10], state[14]);
    BLAKE2S_G(mb32, round, 3, state[3], state[7], state[11], state[15]);

    BLAKE2S_G(mb32, round, 4, state[0], state[5], state[10], state[15]);
    BLAKE2S_G(mb32, round, 5, state[1], state[6], state[11], state[12]);
    BLAKE2S_G(mb32, round, 6, state[2], state[7], state[8], state[13]);
    BLAKE2S_G(mb32, round, 7, state[3], state[4], state[9], state[14]);
}

static void
blake2s_hashblock(uint32_t state[16], uint32_t h[8], uint32_t t[2],
                  const uint8_t message_block[64], uint32_t inc, int is_last)
{
    uint32_t mb32[16];
    int      round;
    int      i;

    for (i = 0; i < 16; i++) {
        mb32[i] = LOAD32_LE(&message_block[(size_t) i * sizeof mb32[0]]);
    }
    memcpy(&state[0], h, 8 * sizeof state[0]);
    memcpy(&state[8], IV, 8 * sizeof state[0]);
    t[0] += inc;
    if (t[0] < inc) {
        t[1]++;
    }
    state[12] ^= t[0];
    state[13] ^= t[1];
    if (is_last) {
        state[14] = ~state[14];
    }
    for (round = 0; round < 10; round++) {
        blake2s_round(state, mb32, round);
    }
    for (i = 0; i < 8; i++) {
        h[i] ^= state[i] ^ state[i + 8];
    }
}

void
blake2s(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len,
        const uint8_t *key, size_t key_len)
{
    uint8_t  out_tmp[32];
    uint32_t state[16];
    uint8_t  block[64];
    uint32_t h[8];
    uint32_t t[2] = { 0 };
    size_t   off;
    int      i;

    memcpy(h, IV, sizeof h);
    h[0] ^= (out_len | (key_len << 8) | (1 << 16) | (1 << 24));
    if (key_len > 0) {
        memset(block, 0, sizeof block);
        memcpy(block, key, key_len);
        blake2s_hashblock(state, h, t, block, 64U, in_len == 0);
    }
    for (off = 0U; in_len > 64U; off += 64U) {
        blake2s_hashblock(state, h, t, &in[off], 64U, 0);
        in_len -= 64U;
    }
    if (in_len > 0U || key_len == 0U) {
        memset(block, 0, sizeof block);
        if (in_len > 0U) {
            memcpy(block, &in[off], in_len);
        }
        blake2s_hashblock(state, h, t, block, (uint32_t) in_len, 1);
    }
    for (i = 0; i < 8; i++) {
        STORE32_LE(&out_tmp[(size_t) i * sizeof h[0]], h[i]);
    }
    memcpy(out, out_tmp, out_len);
}


void
blake2s_nacl(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
)
{
  blake2s (output,  nn, d,  ll, k, kk);
}