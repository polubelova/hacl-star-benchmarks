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


#include "Hacl_Chacha20_Vec512.h"

uint32_t
Hacl_Impl_Chacha20_Vec_chacha20_constants[4U] =
  { (uint32_t)0x61707865U, (uint32_t)0x3320646eU, (uint32_t)0x79622d32U, (uint32_t)0x6b206574U };


static inline void double_round_512(Lib_IntVector_Intrinsics_vec512 *st)
{
  st[0U] = Lib_IntVector_Intrinsics_vec512_add32(st[0U], st[4U]);
  Lib_IntVector_Intrinsics_vec512 std = Lib_IntVector_Intrinsics_vec512_xor(st[12U], st[0U]);
  st[12U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std, (uint32_t)16U);
  st[8U] = Lib_IntVector_Intrinsics_vec512_add32(st[8U], st[12U]);
  Lib_IntVector_Intrinsics_vec512 std0 = Lib_IntVector_Intrinsics_vec512_xor(st[4U], st[8U]);
  st[4U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std0, (uint32_t)12U);
  st[0U] = Lib_IntVector_Intrinsics_vec512_add32(st[0U], st[4U]);
  Lib_IntVector_Intrinsics_vec512 std1 = Lib_IntVector_Intrinsics_vec512_xor(st[12U], st[0U]);
  st[12U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std1, (uint32_t)8U);
  st[8U] = Lib_IntVector_Intrinsics_vec512_add32(st[8U], st[12U]);
  Lib_IntVector_Intrinsics_vec512 std2 = Lib_IntVector_Intrinsics_vec512_xor(st[4U], st[8U]);
  st[4U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std2, (uint32_t)7U);
  st[1U] = Lib_IntVector_Intrinsics_vec512_add32(st[1U], st[5U]);
  Lib_IntVector_Intrinsics_vec512 std3 = Lib_IntVector_Intrinsics_vec512_xor(st[13U], st[1U]);
  st[13U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std3, (uint32_t)16U);
  st[9U] = Lib_IntVector_Intrinsics_vec512_add32(st[9U], st[13U]);
  Lib_IntVector_Intrinsics_vec512 std4 = Lib_IntVector_Intrinsics_vec512_xor(st[5U], st[9U]);
  st[5U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std4, (uint32_t)12U);
  st[1U] = Lib_IntVector_Intrinsics_vec512_add32(st[1U], st[5U]);
  Lib_IntVector_Intrinsics_vec512 std5 = Lib_IntVector_Intrinsics_vec512_xor(st[13U], st[1U]);
  st[13U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std5, (uint32_t)8U);
  st[9U] = Lib_IntVector_Intrinsics_vec512_add32(st[9U], st[13U]);
  Lib_IntVector_Intrinsics_vec512 std6 = Lib_IntVector_Intrinsics_vec512_xor(st[5U], st[9U]);
  st[5U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std6, (uint32_t)7U);
  st[2U] = Lib_IntVector_Intrinsics_vec512_add32(st[2U], st[6U]);
  Lib_IntVector_Intrinsics_vec512 std7 = Lib_IntVector_Intrinsics_vec512_xor(st[14U], st[2U]);
  st[14U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std7, (uint32_t)16U);
  st[10U] = Lib_IntVector_Intrinsics_vec512_add32(st[10U], st[14U]);
  Lib_IntVector_Intrinsics_vec512 std8 = Lib_IntVector_Intrinsics_vec512_xor(st[6U], st[10U]);
  st[6U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std8, (uint32_t)12U);
  st[2U] = Lib_IntVector_Intrinsics_vec512_add32(st[2U], st[6U]);
  Lib_IntVector_Intrinsics_vec512 std9 = Lib_IntVector_Intrinsics_vec512_xor(st[14U], st[2U]);
  st[14U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std9, (uint32_t)8U);
  st[10U] = Lib_IntVector_Intrinsics_vec512_add32(st[10U], st[14U]);
  Lib_IntVector_Intrinsics_vec512 std10 = Lib_IntVector_Intrinsics_vec512_xor(st[6U], st[10U]);
  st[6U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std10, (uint32_t)7U);
  st[3U] = Lib_IntVector_Intrinsics_vec512_add32(st[3U], st[7U]);
  Lib_IntVector_Intrinsics_vec512 std11 = Lib_IntVector_Intrinsics_vec512_xor(st[15U], st[3U]);
  st[15U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std11, (uint32_t)16U);
  st[11U] = Lib_IntVector_Intrinsics_vec512_add32(st[11U], st[15U]);
  Lib_IntVector_Intrinsics_vec512 std12 = Lib_IntVector_Intrinsics_vec512_xor(st[7U], st[11U]);
  st[7U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std12, (uint32_t)12U);
  st[3U] = Lib_IntVector_Intrinsics_vec512_add32(st[3U], st[7U]);
  Lib_IntVector_Intrinsics_vec512 std13 = Lib_IntVector_Intrinsics_vec512_xor(st[15U], st[3U]);
  st[15U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std13, (uint32_t)8U);
  st[11U] = Lib_IntVector_Intrinsics_vec512_add32(st[11U], st[15U]);
  Lib_IntVector_Intrinsics_vec512 std14 = Lib_IntVector_Intrinsics_vec512_xor(st[7U], st[11U]);
  st[7U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std14, (uint32_t)7U);
  st[0U] = Lib_IntVector_Intrinsics_vec512_add32(st[0U], st[5U]);
  Lib_IntVector_Intrinsics_vec512 std15 = Lib_IntVector_Intrinsics_vec512_xor(st[15U], st[0U]);
  st[15U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std15, (uint32_t)16U);
  st[10U] = Lib_IntVector_Intrinsics_vec512_add32(st[10U], st[15U]);
  Lib_IntVector_Intrinsics_vec512 std16 = Lib_IntVector_Intrinsics_vec512_xor(st[5U], st[10U]);
  st[5U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std16, (uint32_t)12U);
  st[0U] = Lib_IntVector_Intrinsics_vec512_add32(st[0U], st[5U]);
  Lib_IntVector_Intrinsics_vec512 std17 = Lib_IntVector_Intrinsics_vec512_xor(st[15U], st[0U]);
  st[15U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std17, (uint32_t)8U);
  st[10U] = Lib_IntVector_Intrinsics_vec512_add32(st[10U], st[15U]);
  Lib_IntVector_Intrinsics_vec512 std18 = Lib_IntVector_Intrinsics_vec512_xor(st[5U], st[10U]);
  st[5U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std18, (uint32_t)7U);
  st[1U] = Lib_IntVector_Intrinsics_vec512_add32(st[1U], st[6U]);
  Lib_IntVector_Intrinsics_vec512 std19 = Lib_IntVector_Intrinsics_vec512_xor(st[12U], st[1U]);
  st[12U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std19, (uint32_t)16U);
  st[11U] = Lib_IntVector_Intrinsics_vec512_add32(st[11U], st[12U]);
  Lib_IntVector_Intrinsics_vec512 std20 = Lib_IntVector_Intrinsics_vec512_xor(st[6U], st[11U]);
  st[6U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std20, (uint32_t)12U);
  st[1U] = Lib_IntVector_Intrinsics_vec512_add32(st[1U], st[6U]);
  Lib_IntVector_Intrinsics_vec512 std21 = Lib_IntVector_Intrinsics_vec512_xor(st[12U], st[1U]);
  st[12U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std21, (uint32_t)8U);
  st[11U] = Lib_IntVector_Intrinsics_vec512_add32(st[11U], st[12U]);
  Lib_IntVector_Intrinsics_vec512 std22 = Lib_IntVector_Intrinsics_vec512_xor(st[6U], st[11U]);
  st[6U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std22, (uint32_t)7U);
  st[2U] = Lib_IntVector_Intrinsics_vec512_add32(st[2U], st[7U]);
  Lib_IntVector_Intrinsics_vec512 std23 = Lib_IntVector_Intrinsics_vec512_xor(st[13U], st[2U]);
  st[13U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std23, (uint32_t)16U);
  st[8U] = Lib_IntVector_Intrinsics_vec512_add32(st[8U], st[13U]);
  Lib_IntVector_Intrinsics_vec512 std24 = Lib_IntVector_Intrinsics_vec512_xor(st[7U], st[8U]);
  st[7U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std24, (uint32_t)12U);
  st[2U] = Lib_IntVector_Intrinsics_vec512_add32(st[2U], st[7U]);
  Lib_IntVector_Intrinsics_vec512 std25 = Lib_IntVector_Intrinsics_vec512_xor(st[13U], st[2U]);
  st[13U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std25, (uint32_t)8U);
  st[8U] = Lib_IntVector_Intrinsics_vec512_add32(st[8U], st[13U]);
  Lib_IntVector_Intrinsics_vec512 std26 = Lib_IntVector_Intrinsics_vec512_xor(st[7U], st[8U]);
  st[7U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std26, (uint32_t)7U);
  st[3U] = Lib_IntVector_Intrinsics_vec512_add32(st[3U], st[4U]);
  Lib_IntVector_Intrinsics_vec512 std27 = Lib_IntVector_Intrinsics_vec512_xor(st[14U], st[3U]);
  st[14U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std27, (uint32_t)16U);
  st[9U] = Lib_IntVector_Intrinsics_vec512_add32(st[9U], st[14U]);
  Lib_IntVector_Intrinsics_vec512 std28 = Lib_IntVector_Intrinsics_vec512_xor(st[4U], st[9U]);
  st[4U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std28, (uint32_t)12U);
  st[3U] = Lib_IntVector_Intrinsics_vec512_add32(st[3U], st[4U]);
  Lib_IntVector_Intrinsics_vec512 std29 = Lib_IntVector_Intrinsics_vec512_xor(st[14U], st[3U]);
  st[14U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std29, (uint32_t)8U);
  st[9U] = Lib_IntVector_Intrinsics_vec512_add32(st[9U], st[14U]);
  Lib_IntVector_Intrinsics_vec512 std30 = Lib_IntVector_Intrinsics_vec512_xor(st[4U], st[9U]);
  st[4U] = Lib_IntVector_Intrinsics_vec512_rotate_left32(std30, (uint32_t)7U);
}

static inline void
chacha20_core_512(
  Lib_IntVector_Intrinsics_vec512 *k,
  Lib_IntVector_Intrinsics_vec512 *ctx,
  uint32_t ctr
)
{
  memcpy(k, ctx, (uint32_t)16U * sizeof (ctx[0U]));
  uint32_t ctr_u32 = (uint32_t)16U * ctr;
  Lib_IntVector_Intrinsics_vec512 cv = Lib_IntVector_Intrinsics_vec512_load32(ctr_u32);
  k[12U] = Lib_IntVector_Intrinsics_vec512_add32(k[12U], cv);
  double_round_512(k);
  double_round_512(k);
  double_round_512(k);
  double_round_512(k);
  double_round_512(k);
  double_round_512(k);
  double_round_512(k);
  double_round_512(k);
  double_round_512(k);
  double_round_512(k);
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[0U], ctx[0U]);
    os[0U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[1U], ctx[1U]);
    os[1U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[2U], ctx[2U]);
    os[2U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[3U], ctx[3U]);
    os[3U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[4U], ctx[4U]);
    os[4U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[5U], ctx[5U]);
    os[5U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[6U], ctx[6U]);
    os[6U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[7U], ctx[7U]);
    os[7U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[8U], ctx[8U]);
    os[8U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[9U], ctx[9U]);
    os[9U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[10U], ctx[10U]);
    os[10U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[11U], ctx[11U]);
    os[11U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[12U], ctx[12U]);
    os[12U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[13U], ctx[13U]);
    os[13U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[14U], ctx[14U]);
    os[14U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = k;
    Lib_IntVector_Intrinsics_vec512 x = Lib_IntVector_Intrinsics_vec512_add32(k[15U], ctx[15U]);
    os[15U] = x;
  }
  k[12U] = Lib_IntVector_Intrinsics_vec512_add32(k[12U], cv);
}

static inline void
chacha20_init_512(Lib_IntVector_Intrinsics_vec512 *ctx, uint8_t *k, uint8_t *n1, uint32_t ctr)
{
  uint32_t ctx1[16U] = { 0U };
  uint32_t *uu____0 = ctx1;
  {
    uint32_t *os = uu____0;
    uint32_t x = Hacl_Impl_Chacha20_Vec_chacha20_constants[0U];
    os[0U] = x;
  }
  {
    uint32_t *os = uu____0;
    uint32_t x = Hacl_Impl_Chacha20_Vec_chacha20_constants[1U];
    os[1U] = x;
  }
  {
    uint32_t *os = uu____0;
    uint32_t x = Hacl_Impl_Chacha20_Vec_chacha20_constants[2U];
    os[2U] = x;
  }
  {
    uint32_t *os = uu____0;
    uint32_t x = Hacl_Impl_Chacha20_Vec_chacha20_constants[3U];
    os[3U] = x;
  }
  uint32_t *uu____1 = ctx1 + (uint32_t)4U;
  {
    uint32_t *os = uu____1;
    uint8_t *bj = k + (uint32_t)0U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[0U] = x;
  }
  {
    uint32_t *os = uu____1;
    uint8_t *bj = k + (uint32_t)1U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[1U] = x;
  }
  {
    uint32_t *os = uu____1;
    uint8_t *bj = k + (uint32_t)2U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[2U] = x;
  }
  {
    uint32_t *os = uu____1;
    uint8_t *bj = k + (uint32_t)3U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[3U] = x;
  }
  {
    uint32_t *os = uu____1;
    uint8_t *bj = k + (uint32_t)4U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[4U] = x;
  }
  {
    uint32_t *os = uu____1;
    uint8_t *bj = k + (uint32_t)5U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[5U] = x;
  }
  {
    uint32_t *os = uu____1;
    uint8_t *bj = k + (uint32_t)6U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[6U] = x;
  }
  {
    uint32_t *os = uu____1;
    uint8_t *bj = k + (uint32_t)7U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[7U] = x;
  }
  ctx1[12U] = ctr;
  uint32_t *uu____2 = ctx1 + (uint32_t)13U;
  {
    uint32_t *os = uu____2;
    uint8_t *bj = n1 + (uint32_t)0U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[0U] = x;
  }
  {
    uint32_t *os = uu____2;
    uint8_t *bj = n1 + (uint32_t)1U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[1U] = x;
  }
  {
    uint32_t *os = uu____2;
    uint8_t *bj = n1 + (uint32_t)2U * (uint32_t)4U;
    uint32_t u = load32_le(bj);
    uint32_t r = u;
    uint32_t x = r;
    os[2U] = x;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[0U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[0U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[1U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[1U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[2U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[2U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[3U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[3U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[4U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[4U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[5U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[5U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[6U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[6U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[7U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[7U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[8U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[8U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[9U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[9U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[10U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[10U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[11U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[11U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[12U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[12U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[13U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[13U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[14U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[14U] = x0;
  }
  {
    Lib_IntVector_Intrinsics_vec512 *os = ctx;
    uint32_t x = ctx1[15U];
    Lib_IntVector_Intrinsics_vec512 x0 = Lib_IntVector_Intrinsics_vec512_load32(x);
    os[15U] = x0;
  }
  Lib_IntVector_Intrinsics_vec512
  ctr1 =
    Lib_IntVector_Intrinsics_vec512_load32s((uint32_t)0U,
      (uint32_t)1U,
      (uint32_t)2U,
      (uint32_t)3U,
      (uint32_t)4U,
      (uint32_t)5U,
      (uint32_t)6U,
      (uint32_t)7U,
      (uint32_t)8U,
      (uint32_t)9U,
      (uint32_t)10U,
      (uint32_t)11U,
      (uint32_t)12U,
      (uint32_t)13U,
      (uint32_t)14U,
      (uint32_t)15U);
  Lib_IntVector_Intrinsics_vec512 c12 = ctx[12U];
  ctx[12U] = Lib_IntVector_Intrinsics_vec512_add32(c12, ctr1);
}

void
Hacl_Chacha20_Vec512_chacha20_encrypt_512(
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr
)
{
  KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec512), (uint32_t)16U);
  Lib_IntVector_Intrinsics_vec512 ctx[16U];
  for (uint32_t _i = 0U; _i < (uint32_t)16U; ++_i)
    ctx[_i] = Lib_IntVector_Intrinsics_vec512_zero;
  chacha20_init_512(ctx, key, n1, ctr);
  uint32_t rem1 = len % (uint32_t)1024U;
  uint32_t nb = len / (uint32_t)1024U;
  uint32_t rem2 = len % (uint32_t)1024U;
  for (uint32_t i0 = (uint32_t)0U; i0 < nb; i0++)
  {
    uint8_t *uu____0 = out + i0 * (uint32_t)1024U;
    uint8_t *uu____1 = text + i0 * (uint32_t)1024U;
    KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec512), (uint32_t)16U);
    Lib_IntVector_Intrinsics_vec512 k[16U];
    for (uint32_t _i = 0U; _i < (uint32_t)16U; ++_i)
      k[_i] = Lib_IntVector_Intrinsics_vec512_zero;
    chacha20_core_512(k, ctx, i0);
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U]);
      }
    }
    Lib_IntVector_Intrinsics_vec512 v0 = k[0U];
    Lib_IntVector_Intrinsics_vec512 v2 = k[1U];
    Lib_IntVector_Intrinsics_vec512 v1 = k[2U];
    Lib_IntVector_Intrinsics_vec512 v3 = k[3U];
    Lib_IntVector_Intrinsics_vec512 v4 = k[4U];
    Lib_IntVector_Intrinsics_vec512 v6 = k[5U];
    Lib_IntVector_Intrinsics_vec512 v5 = k[6U];
    Lib_IntVector_Intrinsics_vec512 v7 = k[7U];
    Lib_IntVector_Intrinsics_vec512 v8 = k[8U];
    Lib_IntVector_Intrinsics_vec512 v10 = k[9U];
    Lib_IntVector_Intrinsics_vec512 v9 = k[10U];
    Lib_IntVector_Intrinsics_vec512 v11 = k[11U];
    Lib_IntVector_Intrinsics_vec512 v12 = k[12U];
    Lib_IntVector_Intrinsics_vec512 v14 = k[13U];
    Lib_IntVector_Intrinsics_vec512 v13 = k[14U];
    Lib_IntVector_Intrinsics_vec512 v15 = k[15U];
    k[0U] = v0;
    k[1U] = v1;
    k[2U] = v2;
    k[3U] = v3;
    k[4U] = v4;
    k[5U] = v5;
    k[6U] = v6;
    k[7U] = v7;
    k[8U] = v8;
    k[9U] = v9;
    k[10U] = v10;
    k[11U] = v11;
    k[12U] = v12;
    k[13U] = v13;
    k[14U] = v14;
    k[15U] = v15;
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)0U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[0U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)0U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)1U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[1U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)1U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)2U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[2U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)2U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)3U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[3U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)3U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)4U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[4U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)4U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)5U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[5U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)5U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)6U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[6U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)6U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)7U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[7U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)7U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)8U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[8U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)8U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)9U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[9U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)9U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)10U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[10U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)10U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)11U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[11U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)11U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)12U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[12U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)12U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)13U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[13U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)13U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)14U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[14U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)14U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)15U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[15U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)15U * (uint32_t)64U, y);
    }
  }
  if (rem2 > (uint32_t)0U)
  {
    uint8_t *uu____2 = out + nb * (uint32_t)1024U;
    uint8_t *uu____3 = text + nb * (uint32_t)1024U;
    uint8_t plain[1024U] = { 0U };
    memcpy(plain, uu____3, rem1 * sizeof (uu____3[0U]));
    KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec512), (uint32_t)16U);
    Lib_IntVector_Intrinsics_vec512 k[16U];
    for (uint32_t _i = 0U; _i < (uint32_t)16U; ++_i)
      k[_i] = Lib_IntVector_Intrinsics_vec512_zero;
    chacha20_core_512(k, ctx, nb);
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U]);
      }
    }
    Lib_IntVector_Intrinsics_vec512 v0 = k[0U];
    Lib_IntVector_Intrinsics_vec512 v2 = k[1U];
    Lib_IntVector_Intrinsics_vec512 v1 = k[2U];
    Lib_IntVector_Intrinsics_vec512 v3 = k[3U];
    Lib_IntVector_Intrinsics_vec512 v4 = k[4U];
    Lib_IntVector_Intrinsics_vec512 v6 = k[5U];
    Lib_IntVector_Intrinsics_vec512 v5 = k[6U];
    Lib_IntVector_Intrinsics_vec512 v7 = k[7U];
    Lib_IntVector_Intrinsics_vec512 v8 = k[8U];
    Lib_IntVector_Intrinsics_vec512 v10 = k[9U];
    Lib_IntVector_Intrinsics_vec512 v9 = k[10U];
    Lib_IntVector_Intrinsics_vec512 v11 = k[11U];
    Lib_IntVector_Intrinsics_vec512 v12 = k[12U];
    Lib_IntVector_Intrinsics_vec512 v14 = k[13U];
    Lib_IntVector_Intrinsics_vec512 v13 = k[14U];
    Lib_IntVector_Intrinsics_vec512 v15 = k[15U];
    k[0U] = v0;
    k[1U] = v1;
    k[2U] = v2;
    k[3U] = v3;
    k[4U] = v4;
    k[5U] = v5;
    k[6U] = v6;
    k[7U] = v7;
    k[8U] = v8;
    k[9U] = v9;
    k[10U] = v10;
    k[11U] = v11;
    k[12U] = v12;
    k[13U] = v13;
    k[14U] = v14;
    k[15U] = v15;
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)0U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[0U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)0U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)1U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[1U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)1U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)2U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[2U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)2U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)3U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[3U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)3U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)4U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[4U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)4U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)5U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[5U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)5U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)6U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[6U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)6U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)7U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[7U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)7U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)8U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[8U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)8U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)9U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[9U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)9U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)10U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[10U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)10U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)11U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[11U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)11U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)12U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[12U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)12U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)13U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[13U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)13U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)14U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[14U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)14U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)15U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[15U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)15U * (uint32_t)64U, y);
    }
    memcpy(uu____2, plain, rem1 * sizeof (plain[0U]));
  }
}

void
Hacl_Chacha20_Vec512_chacha20_decrypt_512(
  uint32_t len,
  uint8_t *out,
  uint8_t *cipher,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr
)
{
  KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec512), (uint32_t)16U);
  Lib_IntVector_Intrinsics_vec512 ctx[16U];
  for (uint32_t _i = 0U; _i < (uint32_t)16U; ++_i)
    ctx[_i] = Lib_IntVector_Intrinsics_vec512_zero;
  chacha20_init_512(ctx, key, n1, ctr);
  uint32_t rem1 = len % (uint32_t)1024U;
  uint32_t nb = len / (uint32_t)1024U;
  uint32_t rem2 = len % (uint32_t)1024U;
  for (uint32_t i0 = (uint32_t)0U; i0 < nb; i0++)
  {
    uint8_t *uu____0 = out + i0 * (uint32_t)1024U;
    uint8_t *uu____1 = cipher + i0 * (uint32_t)1024U;
    KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec512), (uint32_t)16U);
    Lib_IntVector_Intrinsics_vec512 k[16U];
    for (uint32_t _i = 0U; _i < (uint32_t)16U; ++_i)
      k[_i] = Lib_IntVector_Intrinsics_vec512_zero;
    chacha20_core_512(k, ctx, i0);
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U]);
      }
    }
    Lib_IntVector_Intrinsics_vec512 v0 = k[0U];
    Lib_IntVector_Intrinsics_vec512 v2 = k[1U];
    Lib_IntVector_Intrinsics_vec512 v1 = k[2U];
    Lib_IntVector_Intrinsics_vec512 v3 = k[3U];
    Lib_IntVector_Intrinsics_vec512 v4 = k[4U];
    Lib_IntVector_Intrinsics_vec512 v6 = k[5U];
    Lib_IntVector_Intrinsics_vec512 v5 = k[6U];
    Lib_IntVector_Intrinsics_vec512 v7 = k[7U];
    Lib_IntVector_Intrinsics_vec512 v8 = k[8U];
    Lib_IntVector_Intrinsics_vec512 v10 = k[9U];
    Lib_IntVector_Intrinsics_vec512 v9 = k[10U];
    Lib_IntVector_Intrinsics_vec512 v11 = k[11U];
    Lib_IntVector_Intrinsics_vec512 v12 = k[12U];
    Lib_IntVector_Intrinsics_vec512 v14 = k[13U];
    Lib_IntVector_Intrinsics_vec512 v13 = k[14U];
    Lib_IntVector_Intrinsics_vec512 v15 = k[15U];
    k[0U] = v0;
    k[1U] = v1;
    k[2U] = v2;
    k[3U] = v3;
    k[4U] = v4;
    k[5U] = v5;
    k[6U] = v6;
    k[7U] = v7;
    k[8U] = v8;
    k[9U] = v9;
    k[10U] = v10;
    k[11U] = v11;
    k[12U] = v12;
    k[13U] = v13;
    k[14U] = v14;
    k[15U] = v15;
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)0U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[0U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)0U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)1U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[1U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)1U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)2U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[2U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)2U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)3U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[3U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)3U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)4U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[4U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)4U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)5U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[5U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)5U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)6U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[6U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)6U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)7U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[7U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)7U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)8U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[8U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)8U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)9U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[9U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)9U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)10U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[10U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)10U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)11U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[11U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)11U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)12U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[12U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)12U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)13U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[13U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)13U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)14U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[14U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)14U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(uu____1 + (uint32_t)15U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[15U]);
      Lib_IntVector_Intrinsics_vec512_store_le(uu____0 + (uint32_t)15U * (uint32_t)64U, y);
    }
  }
  if (rem2 > (uint32_t)0U)
  {
    uint8_t *uu____2 = out + nb * (uint32_t)1024U;
    uint8_t *uu____3 = cipher + nb * (uint32_t)1024U;
    uint8_t plain[1024U] = { 0U };
    memcpy(plain, uu____3, rem1 * sizeof (uu____3[0U]));
    KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec512), (uint32_t)16U);
    Lib_IntVector_Intrinsics_vec512 k[16U];
    for (uint32_t _i = 0U; _i < (uint32_t)16U; ++_i)
      k[_i] = Lib_IntVector_Intrinsics_vec512_zero;
    chacha20_core_512(k, ctx, nb);
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)0U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)1U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)2U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)3U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)4U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)5U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)6U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U];
        k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low32(inp_kj,
            k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
        k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high32(inp_kj,
            k[(uint32_t)7U * (uint32_t)2U + (uint32_t)0U + (uint32_t)1U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U];
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)0U + (uint32_t)2U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)0U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)1U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)2U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U];
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
        k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high64(inp_kj,
            k[(uint32_t)3U * (uint32_t)4U + (uint32_t)1U + (uint32_t)2U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)0U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)1U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)2U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U];
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
        k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)0U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
      }
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U];
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
        k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high128(inp_kj,
            k[(uint32_t)1U * (uint32_t)8U + (uint32_t)3U + (uint32_t)4U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)0U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)1U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)2U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)3U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)4U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)5U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)6U + (uint32_t)8U]);
      }
    }
    {
      {
        Lib_IntVector_Intrinsics_vec512 inp_kj = k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U];
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U] =
          Lib_IntVector_Intrinsics_vec512_interleave_low256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U]);
        k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U] =
          Lib_IntVector_Intrinsics_vec512_interleave_high256(inp_kj,
            k[(uint32_t)0U * (uint32_t)16U + (uint32_t)7U + (uint32_t)8U]);
      }
    }
    Lib_IntVector_Intrinsics_vec512 v0 = k[0U];
    Lib_IntVector_Intrinsics_vec512 v2 = k[1U];
    Lib_IntVector_Intrinsics_vec512 v1 = k[2U];
    Lib_IntVector_Intrinsics_vec512 v3 = k[3U];
    Lib_IntVector_Intrinsics_vec512 v4 = k[4U];
    Lib_IntVector_Intrinsics_vec512 v6 = k[5U];
    Lib_IntVector_Intrinsics_vec512 v5 = k[6U];
    Lib_IntVector_Intrinsics_vec512 v7 = k[7U];
    Lib_IntVector_Intrinsics_vec512 v8 = k[8U];
    Lib_IntVector_Intrinsics_vec512 v10 = k[9U];
    Lib_IntVector_Intrinsics_vec512 v9 = k[10U];
    Lib_IntVector_Intrinsics_vec512 v11 = k[11U];
    Lib_IntVector_Intrinsics_vec512 v12 = k[12U];
    Lib_IntVector_Intrinsics_vec512 v14 = k[13U];
    Lib_IntVector_Intrinsics_vec512 v13 = k[14U];
    Lib_IntVector_Intrinsics_vec512 v15 = k[15U];
    k[0U] = v0;
    k[1U] = v1;
    k[2U] = v2;
    k[3U] = v3;
    k[4U] = v4;
    k[5U] = v5;
    k[6U] = v6;
    k[7U] = v7;
    k[8U] = v8;
    k[9U] = v9;
    k[10U] = v10;
    k[11U] = v11;
    k[12U] = v12;
    k[13U] = v13;
    k[14U] = v14;
    k[15U] = v15;
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)0U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[0U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)0U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)1U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[1U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)1U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)2U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[2U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)2U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)3U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[3U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)3U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)4U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[4U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)4U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)5U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[5U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)5U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)6U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[6U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)6U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)7U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[7U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)7U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)8U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[8U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)8U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)9U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[9U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)9U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)10U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[10U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)10U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)11U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[11U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)11U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)12U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[12U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)12U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)13U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[13U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)13U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)14U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[14U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)14U * (uint32_t)64U, y);
    }
    {
      Lib_IntVector_Intrinsics_vec512
      x = Lib_IntVector_Intrinsics_vec512_load_le(plain + (uint32_t)15U * (uint32_t)64U);
      Lib_IntVector_Intrinsics_vec512 y = Lib_IntVector_Intrinsics_vec512_xor(x, k[15U]);
      Lib_IntVector_Intrinsics_vec512_store_le(plain + (uint32_t)15U * (uint32_t)64U, y);
    }
    memcpy(uu____2, plain, rem1 * sizeof (plain[0U]));
  }
}


void chacha20_hacl_vec512(
  uint32_t len,
  uint8_t *out,
  uint8_t *text,
  uint8_t *key,
  uint8_t *n1,
  uint32_t ctr
)
{
  Hacl_Chacha20_Vec512_chacha20_encrypt_512 (len, out, text, key, n1, ctr);
}


