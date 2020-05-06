/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is based in part on Andrew Moon's poly1305-donna, which is in the
 * public domain.
 */

#include "kbench-common.h"

enum {
	POLY1305_BLOCK_SIZE = 16,
	POLY1305_KEY_SIZE = 32,
	POLY1305_MAC_SIZE = 16
};

struct poly1305_ctx {
	u8 opaque[24 * sizeof(u64)];
	u32 nonce[4];
	u8 data[POLY1305_BLOCK_SIZE];
	size_t num;
} __aligned(8);


typedef __uint128_t u128;

struct poly1305_internal {
	u64 r[3];
	u64 h[3];
	u64 s[2];
};

static void poly1305_init_generic(void *ctx, const u8 key[16])
{
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;
	u64 t0, t1;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	t0 = load64_le(&key[0]);
	t1 = load64_le(&key[8]);

	st->r[0] = (t0) &0xffc0fffffff;
	st->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
	st->r[2] = ((t1 >> 24)) & 0x00ffffffc0f;

	st->s[0] = st->r[1] * 20;
	st->s[1] = st->r[2] * 20;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
}

static void poly1305_blocks_generic(void *ctx, const u8 *input, size_t len,
				    const u32 padbit)
{
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;
	const u64 hibit = padbit ? (1ULL << 40) : 0;
	u64 r0, r1, r2;
	u64 s1, s2;
	u64 h0, h1, h2;
	u64 c;
	u128 d0, d1, d2, d;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];

	s1 = st->s[0];
	s2 = st->s[1];

	while (len >= POLY1305_BLOCK_SIZE) {
		u64 t0, t1;

		/* h += m[i] */
		t0 = load64_le(&input[0]);
		t1 = load64_le(&input[8]);

		h0 += ((t0) &0xfffffffffff);
		h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
		h2 += (((t1 >> 24)) & 0x3ffffffffff) | hibit;

		/* h *= r */
		d0 = ((u128)h0 * r0);
		d = ((u128)h1 * s2);
		d0 += d;
		d = ((u128)h2 * s1);
		d0 += d;
		d1 = ((u128)h0 * r1);
		d = ((u128)h1 * r0);
		d1 += d;
		d = ((u128)h2 * s2);
		d1 += d;
		d2 = ((u128)h0 * r2);
		d = ((u128)h1 * r1);
		d2 += d;
		d = ((u128)h2 * r0);
		d2 += d;

		/* (partial) h %= p */
		c = (u64)(d0 >> 44);
		h0 = (u64)d0 & 0xfffffffffff;
		d1 += c;
		c = (u64)(d1 >> 44);
		h1 = (u64)d1 & 0xfffffffffff;
		d2 += c;
		c = (u64)(d2 >> 42);
		h2 = (u64)d2 & 0x3ffffffffff;
		h0 += c * 5;
		c = (h0 >> 44);
		h0 = h0 & 0xfffffffffff;
		h1 += c;

		input += POLY1305_BLOCK_SIZE;
		len -= POLY1305_BLOCK_SIZE;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
}

static void poly1305_emit_generic(void *ctx, u8 mac[16], const u32 nonce[4])
{
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;
	u64 h0, h1, h2, c;
	u64 g0, g1, g2;
	u64 t0, t1;

	/* fully carry h */
	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];

	c = (h1 >> 44);
	h1 &= 0xfffffffffff;
	h2 += c;
	c = (h2 >> 42);
	h2 &= 0x3ffffffffff;
	h0 += c * 5;
	c = (h0 >> 44);
	h0 &= 0xfffffffffff;
	h1 += c;
	c = (h1 >> 44);
	h1 &= 0xfffffffffff;
	h2 += c;
	c = (h2 >> 42);
	h2 &= 0x3ffffffffff;
	h0 += c * 5;
	c = (h0 >> 44);
	h0 &= 0xfffffffffff;
	h1 += c;

	/* compute h + -p */
	g0 = h0 + 5;
	c  = (g0 >> 44);
	g0 &= 0xfffffffffff;
	g1 = h1 + c;
	c  = (g1 >> 44);
	g1 &= 0xfffffffffff;
	g2 = h2 + c - (1ULL << 42);

	/* select h if h < p, or h + -p if h >= p */
	c = (g2 >> ((sizeof(u64) * 8) - 1)) - 1;
	g0 &= c;
	g1 &= c;
	g2 &= c;
	c  = ~c;
	h0 = (h0 & c) | g0;
	h1 = (h1 & c) | g1;
	h2 = (h2 & c) | g2;

	/* h = (h + nonce) */
	t0 = ((u64)nonce[1] << 32) | nonce[0];
	t1 = ((u64)nonce[3] << 32) | nonce[2];

	h0 += ((t0) &0xfffffffffff);
	c = (h0 >> 44);
	h0 &= 0xfffffffffff;
	h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c;
	c = (h1 >> 44);
	h1 &= 0xfffffffffff;
	h2 += (((t1 >> 24)) & 0x3ffffffffff) + c;
	h2 &= 0x3ffffffffff;

	/* mac = h % (2^128) */
	h0 = (h0 | (h1 << 44));
	h1 = ((h1 >> 20) | (h2 << 24));

	store64_le(&mac[0],h0);
	store64_le(&mac[8],h1);
}

void poly1305_donna64(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)
{
	size_t rem;
	struct poly1305_ctx ctx;
	ctx.nonce[0] = load32_le(&k[16]);
	ctx.nonce[1] = load32_le(&k[20]);
	ctx.nonce[2] = load32_le(&k[24]);
	ctx.nonce[3] = load32_le(&k[28]);
	poly1305_init_generic(ctx.opaque, k);
	ctx.num = 0;

	rem = inlen % POLY1305_BLOCK_SIZE;
	inlen -= rem;

	if (inlen >= POLY1305_BLOCK_SIZE) {
		poly1305_blocks_generic(ctx.opaque, in, inlen, 1);
		in += inlen;
	}
	if (rem) {
		memcpy(ctx.data, in, rem);
		ctx.data[rem++] = 1;   /* pad bit */
		while (rem < POLY1305_BLOCK_SIZE)
			ctx.data[rem++] = 0;
		poly1305_blocks_generic(ctx.opaque, ctx.data, POLY1305_BLOCK_SIZE, 0);
	}

	poly1305_emit_generic(ctx.opaque, out, ctx.nonce);
}
