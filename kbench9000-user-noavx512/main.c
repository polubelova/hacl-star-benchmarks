/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef unsigned long long cycles_t;

#define ARRAY_SIZE(a)                               \
  ((sizeof(a) / sizeof(*(a))) /                     \
   (size_t)(!(sizeof(a) % sizeof(*(a)))))

int dummy;

enum { POLY1305_MAC_SIZE = 16, POLY1305_KEY_SIZE = 32 };
#include "test_vectors.h"

static __inline__ cycles_t get_cycles(void)
{
  uint64_t rax,rdx,aux;
  asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) : : );
  return (rdx << 32) + rax;
}

#define declare_it(name) \
bool poly1305_ ## name(u8 tag[POLY1305_MAC_SIZE], const u8 * msg, const u32 len, const u8 key[POLY1305_KEY_SIZE]); \
static inline int name(size_t len) \
{ \
	return poly1305_ ## name(dummy_out, input_data, len, input_key); \
}

#define do_it(name) do { \
	for (i = 0; i < WARMUP; ++i) \
		ret |= name(sizeof(input_data)); \
	for (j = 0, s = STARTING_SIZE; j <= DOUBLING_STEPS; ++j, s *= 2) { \
	        trial_times[0] = get_cycles(); \
		for (i = 1; i <= TRIALS; ++i) { \
			ret |= name(s); \
		        trial_times[i] = get_cycles(); } \
		for (i = 0; i < TRIALS; ++i) \
		        trial_times[i] = trial_times[i+1] - trial_times[i]; \
		qsort(trial_times, TRIALS, sizeof(cycles_t), compare_cycles); \
		median_ ## name[j] = trial_times[TRIALS/2]; \
	} \
} while (0)

#define test_it(name, before, after) do { \
	memset(out, __LINE__, POLY1305_MAC_SIZE); \
	before; \
	ret = poly1305_ ## name(out, poly1305_testvecs[i].input, poly1305_testvecs[i].ilen, poly1305_testvecs[i].key); \
	after; \
	if (memcmp(out, poly1305_testvecs[i].output, POLY1305_MAC_SIZE)) { \
		fprintf(stderr,#name " self-test %zu: FAIL\n", i + 1); \
		return false; \
	} \
} while (0)

#define report_it(name) do { \
	char dec[20]; \
	size_t l; \
	fprintf(stderr,"%11s",#name); \
	for (j = 0, s = STARTING_SIZE; j <= DOUBLING_STEPS; ++j, s *= 2) { \
	        fprintf(stderr, " %6.2f", (double)(median_ ## name[j]) / s); \
	} \
	fprintf(stderr, "\n"); \
} while (0)

enum { WARMUP = 50000, TRIALS = 10000, IDLE = 1 * 1000, STARTING_SIZE = 1024, DOUBLING_STEPS = 5 };
u8 dummy_out[POLY1305_MAC_SIZE];
u8 input_key[POLY1305_KEY_SIZE];
u8 input_data[STARTING_SIZE * (1ULL << DOUBLING_STEPS)];

//declare_it(ref)
declare_it(ossl_c)
//declare_it(ossl_amd64)
//declare_it(ossl_avx)
//declare_it(ossl_avx2)
//declare_it(ossl_avx512)
declare_it(donna32)
declare_it(donna64)
declare_it(hacl32)
declare_it(hacl64)
declare_it(hacl32x1)
declare_it(hacl128)
declare_it(hacl256)
declare_it(jazz256)
declare_it(hacl256_55)
declare_it(hacl256_52)
declare_it(hacl256_53)
//declare_it(hacl512)

static int compare_cycles(const void *a, const void *b)
{
	return *((cycles_t *)a) - *((cycles_t *)b);
}

static bool verify(void)
{
	int ret;
	size_t i = 0;
	u8 out[POLY1305_MAC_SIZE];

	for (i = 0; i < ARRAY_SIZE(poly1305_testvecs); ++i) {
	  //		test_it(ref, {}, {});
		test_it(ossl_c, {}, {});
		test_it(donna32, {}, {});
		test_it(donna64, {}, {});
		test_it(hacl32, {}, {});
		test_it(hacl32x1, {}, {});
		test_it(hacl64, {}, {});
		test_it(hacl128, {}, {});
		test_it(hacl256, {}, {});
		test_it(jazz256, {}, {});
		test_it(hacl256_55, {}, {});
		test_it(hacl256_52, {}, {});
		test_it(hacl256_53, {}, {});
//		test_it(hacl512, {}, {});
//		test_it(ossl_amd64, {}, {});
//		test_it(ossl_avx, {}, {});
//		test_it(ossl_avx2, {}, {});
//		test_it(ossl_avx512, {}, {});
	}
	return true;
}

int main()
{
	size_t s;
	int ret = 0, i, j;
	cycles_t median_ref[DOUBLING_STEPS+1];
	cycles_t median_ossl_c[DOUBLING_STEPS + 1];
	cycles_t median_ossl_amd64[DOUBLING_STEPS + 1];
	cycles_t median_ossl_avx[DOUBLING_STEPS + 1];
	cycles_t median_ossl_avx2[DOUBLING_STEPS + 1];
	cycles_t median_ossl_avx512[DOUBLING_STEPS + 1];
	cycles_t median_donna32[DOUBLING_STEPS + 1];
	cycles_t median_donna64[DOUBLING_STEPS + 1];
	cycles_t median_hacl32[DOUBLING_STEPS + 1];
	cycles_t median_hacl32x1[DOUBLING_STEPS + 1];
	cycles_t median_hacl128[DOUBLING_STEPS + 1];
	cycles_t median_hacl256[DOUBLING_STEPS + 1];
	cycles_t median_jazz256[DOUBLING_STEPS + 1];
	cycles_t median_hacl256_55[DOUBLING_STEPS + 1];
	cycles_t median_hacl256_52[DOUBLING_STEPS + 1];
	cycles_t median_hacl256_53[DOUBLING_STEPS + 1];
//	cycles_t median_hacl512[DOUBLING_STEPS + 1];
	cycles_t median_hacl64[DOUBLING_STEPS + 1];
	unsigned long flags;
	cycles_t* trial_times = calloc(TRIALS + 1, sizeof(cycles_t));

	if (!verify())
		return -1;

	for (i = 0; i < sizeof(input_data); ++i)
		input_data[i] = i;
	for (i = 0; i < sizeof(input_key); ++i)
		input_key[i] = i;

	//	do_it(ref);
	do_it(ossl_c);
	do_it(donna32);
	do_it(donna64);
	do_it(hacl32);
	do_it(hacl32x1);
	do_it(hacl128);
	do_it(hacl256);
	do_it(jazz256);
	do_it(hacl256_55);
	do_it(hacl256_53);
	do_it(hacl256_52);
//	do_it(hacl512);
	do_it(hacl64);
//	do_it(ossl_amd64);
//	do_it(ossl_avx);
//	do_it(ossl_avx2);
//	do_it(ossl_avx512);
	fprintf(stderr,"%11s","");
	for (j = 0, s = STARTING_SIZE; j <= DOUBLING_STEPS; ++j, s *= 2) \
		fprintf(stderr, " \x1b[4m%6zu\x1b[24m", s);
	fprintf(stderr,"\n");
	report_it(ossl_c);
	report_it(donna32);
	report_it(donna64);
	report_it(hacl32);
	report_it(hacl32x1);
	report_it(hacl64);
	report_it(hacl128);
	report_it(hacl256);
	report_it(jazz256);
	report_it(hacl256_55);
	report_it(hacl256_53);
	report_it(hacl256_52);
//	report_it(hacl512);
//	report_it(ossl_amd64);
//	report_it(ossl_avx);
//	report_it(ossl_avx2);
//	report_it(ossl_avx512);

	/* Don't let compiler be too clever. */
	dummy = ret;

	/* We should never actually agree to insert the module. Choosing
	 * -0x1000 here is an amazing hack. It causes the kernel to not
	 * actually load the module, while the standard userspace tools
	 * don't return an error, because it's too big. */
	free(trial_times);
	return -0x1000;
}

