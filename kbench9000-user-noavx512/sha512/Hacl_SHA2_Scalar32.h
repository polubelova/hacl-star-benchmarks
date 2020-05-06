/* MIT License
 *
 * Copyright (c) 2016-2020 INRIA, CMU and Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <string.h>
#include <inttypes.h>
#include "lowstar_endianness.h"
#include <stdbool.h>
#include "stdint.h"

typedef unsigned __int128 FStar_UInt128_uint128;
typedef FStar_UInt128_uint128 FStar_UInt128_t, uint128_t;

#define KRML_CHECK_SIZE(a,b) {}

#ifndef __Hacl_SHA2_Scalar32_H
#define __Hacl_SHA2_Scalar32_H

#include "Hacl_SHA2_Generic.h"

inline static void store128_be(uint8_t *b, uint128_t n) {
  store64_be(b, (uint64_t)(n >> 64));
  store64_be(b + 8, (uint64_t)n);
}

typedef struct K____uint8_t___uint8_t__s
{
  uint8_t *fst;
  uint8_t *snd;
}
K____uint8_t___uint8_t_;

void Hacl_SHA2_Scalar32_sha256(uint8_t *h, uint32_t len, uint8_t *b);

void Hacl_SHA2_Scalar32_sha512(uint8_t *h, uint32_t len, uint8_t *b);

#define __Hacl_SHA2_Scalar32_H_DEFINED
#endif