/* SPDX-License-Identifier: OpenSSL OR (BSD-3-Clause OR GPL-2.0)
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
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

struct poly1305_internal {
	u32 h[5];
	u32 r[4];
};

static void poly1305_init_generic(void *ctx, const u8 key[16])
{
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	st->r[0] = load32_le(&key[0]) & 0x0fffffff;
	st->r[1] = load32_le(&key[4]) & 0x0ffffffc;
	st->r[2] = load32_le(&key[8]) & 0x0ffffffc;
	st->r[3] = load32_le(&key[12]) & 0x0ffffffc;
}

static void poly1305_blocks_generic(void *ctx, const u8 *inp, size_t len,
				    const u32 padbit)
{
#define CONSTANT_TIME_CARRY(a, b)                                              \
	((a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1))
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;
	u32 r0, r1, r2, r3;
	u32 s1, s2, s3;
	u32 h0, h1, h2, h3, h4, c;
	u64 d0, d1, d2, d3;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];
	r3 = st->r[3];

	s1 = r1 + (r1 >> 2);
	s2 = r2 + (r2 >> 2);
	s3 = r3 + (r3 >> 2);

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	while (len >= POLY1305_BLOCK_SIZE) {
		/* h += m[i] */
		h0 = (u32)(d0 = (u64)h0 + (0       ) + load32_le(&inp[0]));
		h1 = (u32)(d1 = (u64)h1 + (d0 >> 32) + load32_le(&inp[4]));
		h2 = (u32)(d2 = (u64)h2 + (d1 >> 32) + load32_le(&inp[8]));
		h3 = (u32)(d3 = (u64)h3 + (d2 >> 32) + load32_le(&inp[12]));
		h4 += (u32)(d3 >> 32) + padbit;

		/* h *= r "%" p, where "%" stands for "partial remainder" */
		d0 = ((u64)h0 * r0) +
		     ((u64)h1 * s3) +
		     ((u64)h2 * s2) +
		     ((u64)h3 * s1);
		d1 = ((u64)h0 * r1) +
		     ((u64)h1 * r0) +
		     ((u64)h2 * s3) +
		     ((u64)h3 * s2) +
		     (h4 * s1);
		d2 = ((u64)h0 * r2) +
		     ((u64)h1 * r1) +
		     ((u64)h2 * r0) +
		     ((u64)h3 * s3) +
		     (h4 * s2);
		d3 = ((u64)h0 * r3) +
		     ((u64)h1 * r2) +
		     ((u64)h2 * r1) +
		     ((u64)h3 * r0) +
		     (h4 * s3);
		h4 = (h4 * r0);

		/* last reduction step: */
		/* a) h4:h0 = h4<<128 + d3<<96 + d2<<64 + d1<<32 + d0 */
		h0 = (u32)d0;
		h1 = (u32)(d1 += d0 >> 32);
		h2 = (u32)(d2 += d1 >> 32);
		h3 = (u32)(d3 += d2 >> 32);
		h4 += (u32)(d3 >> 32);
		/* b) (h4:h0 += (h4:h0>>130) * 5) %= 2^130 */
		c = (h4 >> 2) + (h4 & ~3U);
		h4 &= 3;
		h0 += c;
		h1 += (c = CONSTANT_TIME_CARRY(h0, c));
		h2 += (c = CONSTANT_TIME_CARRY(h1, c));
		h3 += (c = CONSTANT_TIME_CARRY(h2, c));
		h4 += CONSTANT_TIME_CARRY(h3, c);
		/*
		 * Occasional overflows to 3rd bit of h4 are taken care of
		 * "naturally". If after this point we end up at the top of
		 * this loop, then the overflow bit will be accounted for
		 * in next iteration. If we end up in poly1305_emit, then
		 * comparison to modulus below will still count as "carry
		 * into 131st bit", so that properly reduced value will be
		 * picked in conditional move.
		 */

		inp += POLY1305_BLOCK_SIZE;
		len -= POLY1305_BLOCK_SIZE;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
#undef CONSTANT_TIME_CARRY
}

static void poly1305_emit_generic(void *ctx, u8 mac[16], const u32 nonce[4])
{
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;
	u32 h0, h1, h2, h3, h4;
	u32 g0, g1, g2, g3, g4;
	u64 t;
	u32 mask;

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	/* compare to modulus by computing h + -p */
	g0 = (u32)(t = (u64)h0 + 5);
	g1 = (u32)(t = (u64)h1 + (t >> 32));
	g2 = (u32)(t = (u64)h2 + (t >> 32));
	g3 = (u32)(t = (u64)h3 + (t >> 32));
	g4 = h4 + (u32)(t >> 32);

	/* if there was carry into 131st bit, h3:h0 = g3:g0 */
	mask = 0 - (g4 >> 2);
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;

	/* mac = (h + nonce) % (2^128) */
	h0 = (u32)(t = (u64)h0 + nonce[0]);
	h1 = (u32)(t = (u64)h1 + (t >> 32) + nonce[1]);
	h2 = (u32)(t = (u64)h2 + (t >> 32) + nonce[2]);
	h3 = (u32)(t = (u64)h3 + (t >> 32) + nonce[3]);

	store32_le(h0, &mac[0]);
	store32_le(h1, &mac[4]);
	store32_le(h2, &mac[8]);
	store32_le(h3, &mac[12]);
}


void poly1305_ossl_c(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)
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

