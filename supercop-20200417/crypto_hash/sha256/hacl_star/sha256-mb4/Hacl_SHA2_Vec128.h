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


#include "libintvector.h"
#include <string.h>
#include <inttypes.h>
#include "lowstar_endianness.h"
#include <stdbool.h>
#include "stdint.h"

#ifndef __Hacl_SHA2_Vec128_H
#define __Hacl_SHA2_Vec128_H

#include "Hacl_SHA2_Generic.h"

#define KRML_CHECK_SIZE(a,b) {}



typedef struct K____uint8_t___uint8_t__s
{
  uint8_t *fst;
  uint8_t *snd;
}
K____uint8_t___uint8_t_;

typedef struct K____uint8_t__K____uint8_t___uint8_t__s
{
  uint8_t *fst;
  K____uint8_t___uint8_t_ snd;
}
K____uint8_t__K____uint8_t___uint8_t_;

typedef struct K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__s
{
  uint8_t *fst;
  K____uint8_t__K____uint8_t___uint8_t_ snd;
}
K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_;

typedef struct K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__s
{
  uint8_t *fst;
  K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_ snd;
}
K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_;

typedef struct
K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__s
{
  uint8_t *fst;
  K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_ snd;
}
K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_;

typedef struct
K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__s
{
  uint8_t *fst;
  K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_ snd;
}
K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_;

typedef struct
K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__s
{
  uint8_t *fst;
  K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_
  snd;
}
K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_;

typedef struct
K___K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__s
{
  K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_
  fst;
  K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_
  snd;
}
K___K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_;


typedef struct
K___K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__s
{
  K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_ fst;
  K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_ snd;
}
K___K____uint8_t__K____uint8_t__K____uint8_t___uint8_t__K____uint8_t__K____uint8_t__K____uint8_t___uint8_t_;



void
Hacl_SHA2_Vec128_sha256_4(
  uint8_t *r0,
  uint8_t *r1,
  uint8_t *r2,
  uint8_t *r3,
  uint32_t len,
  uint8_t *b0,
  uint8_t *b1,
  uint8_t *b2,
  uint8_t *b3
);

#define __Hacl_SHA2_Vec128_H_DEFINED
#endif
