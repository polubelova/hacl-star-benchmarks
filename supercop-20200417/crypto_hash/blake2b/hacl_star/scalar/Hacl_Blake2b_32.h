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

#ifndef __Hacl_Blake2b_32_H
#define __Hacl_Blake2b_32_H

#include "Hacl_Impl_Blake2_Constants.h"


typedef struct K___uint32_t_uint32_t_s
{
  uint32_t fst;
  uint32_t snd;
}
K___uint32_t_uint32_t;

void
Hacl_Blake2b_32_blake2b(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
);

#define __Hacl_Blake2b_32_H_DEFINED
#endif
