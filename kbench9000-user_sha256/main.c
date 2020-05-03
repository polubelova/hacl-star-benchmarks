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

#include "test_vectors.h"

static __inline__ cycles_t get_cycles(void)
{
  uint64_t rax,rdx,aux;
  asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) : : );
  return (rdx << 32) + rax;
}


#define declare_it(name) \
void sha2_ ## name(u8* input_data,  u32 len, u8 * output); \
static inline int name(size_t len) \
{ \
	sha2_ ## name(input_data, len, dummy_out); \
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
	memset(out, __LINE__, vectors2b[i].expected_len); \
	before; \
	sha2_ ## name(vectors2b[i].input, vectors2b[i].input_len, out); \
	after; \
	if (memcmp(out, vectors2b[i].expected, vectors2b[i].expected_len)) { \
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
u8 dummy_out[1000];
u8 input_key[1000];
u8 input_data[1000 * (1ULL << DOUBLING_STEPS)];

declare_it(hacl)
declare_it(openssl)
// declare_it(nacl)
// declare_it(ref)

static int compare_cycles(const void *a, const void *b)
{
	return *((cycles_t *)a) - *((cycles_t *)b);
}

static bool verify(void)
{
	int ret;
	size_t i = 0;
	u8 out[1000];

	// NB: Test is done using only one test vector, so I deleted the loop
	test_it(hacl, {}, {});
	test_it(openssl, {}, {});
	// test_it(nacl, {}, {});
	// test_it(ref, {}, {});

	return true;
}

int main()
{
	size_t s;
	int ret = 0, i, j;
	cycles_t median_hacl[DOUBLING_STEPS+1];
	cycles_t median_openssl[DOUBLING_STEPS+1];
	// cycles_t median_ref[DOUBLING_STEPS+1];

	unsigned long flags;
	cycles_t* trial_times = calloc(TRIALS + 1, sizeof(cycles_t));

	if (!verify())
		return -1;

	for (i = 0; i < sizeof(input_data); ++i)
		input_data[i] = i;
	for (i = 0; i < sizeof(input_key); ++i)
		input_key[i] = i;

	do_it(hacl);
	do_it(openssl);
	// do_it(nacl);
	// do_it(ref);

	fprintf(stderr,"%11s","");
	for (j = 0, s = STARTING_SIZE; j <= DOUBLING_STEPS; ++j, s *= 2) \
		fprintf(stderr, " \x1b[4m%6zu\x1b[24m", s);
	fprintf(stderr,"\n");

	report_it(hacl);
	report_it(openssl);
	// report_it(nacl);
	// report_it(ref);

	/* Don't let compiler be too clever. */
	// Why not? 
	dummy = ret;

	/* We should never actually agree to insert the module. Choosing
	 * -0x1000 here is an amazing hack. It causes the kernel to not
	 * actually load the module, while the standard userspace tools
	 * don't return an error, because it's too big. */
	free(trial_times);
	return -0x1000;
}

