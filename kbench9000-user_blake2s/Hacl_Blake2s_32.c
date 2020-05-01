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


#include "types.h"
// #include "lowstar_endianness.h"
#include <string.h>
// #include "target.h"
#include <stdbool.h>
#include "libintvector.h"
#include "kbench-common.h"

#include "kremlib.h"
#include "Hacl_Impl_Blake2_Constants.h"
// #include "Hacl_Blake2b_256.h"



static inline void
blake2s_update_block(uint32_t *wv, uint32_t *hash, bool flag, uint64_t totlen, uint8_t *d)
{
  uint32_t mask[4U] = { 0U };
  uint32_t wv_14;
  if (flag)
  {
    wv_14 = (uint32_t)0xFFFFFFFFU;
  }
  else
  {
    wv_14 = (uint32_t)0U;
  }
  uint32_t wv_15 = (uint32_t)0U;
  mask[0U] = (uint32_t)totlen;
  mask[1U] = (uint32_t)(totlen >> (uint32_t)32U);
  mask[2U] = wv_14;
  mask[3U] = wv_15;
  memcpy(wv, hash, (uint32_t)4U * (uint32_t)4U * sizeof (hash[0U]));
  uint32_t *wv3 = wv + (uint32_t)3U * (uint32_t)4U;
  {
    uint32_t *os = wv3;
    uint32_t x = wv3[0U] ^ mask[0U];
    os[0U] = x;
  }
  {
    uint32_t *os = wv3;
    uint32_t x = wv3[1U] ^ mask[1U];
    os[1U] = x;
  }
  {
    uint32_t *os = wv3;
    uint32_t x = wv3[2U] ^ mask[2U];
    os[2U] = x;
  }
  {
    uint32_t *os = wv3;
    uint32_t x = wv3[3U] ^ mask[3U];
    os[3U] = x;
  }
  for (uint32_t i0 = (uint32_t)0U; i0 < (uint32_t)10U; i0++)
  {
    uint32_t start_idx = i0 % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint32_t), (uint32_t)4U * (uint32_t)4U);
    uint32_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint32_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint32_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint32_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint32_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t s0 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx];
    uint32_t s1 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)1U];
    uint32_t s2 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)2U];
    uint32_t s3 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)3U];
    uint32_t s4 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)4U];
    uint32_t s5 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)5U];
    uint32_t s6 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)6U];
    uint32_t s7 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)7U];
    uint32_t s8 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)8U];
    uint32_t s9 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)9U];
    uint32_t s10 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)10U];
    uint32_t s11 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)11U];
    uint32_t s12 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)12U];
    uint32_t s13 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)13U];
    uint32_t s14 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)14U];
    uint32_t s15 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)15U];
    uint32_t nb = (uint32_t)4U;
    uint8_t *b00 = d + s0 * nb;
    uint8_t *b10 = d + s2 * nb;
    uint8_t *b20 = d + s4 * nb;
    uint8_t *b30 = d + s6 * nb;
    uint32_t u0 = load32_le(b00);
    uint32_t u00 = u0;
    uint32_t u1 = load32_le(b10);
    uint32_t u11 = u1;
    uint32_t u2 = load32_le(b20);
    uint32_t u20 = u2;
    uint32_t u3 = load32_le(b30);
    uint32_t u30 = u3;
    r00[0U] = u00;
    r00[1U] = u11;
    r00[2U] = u20;
    r00[3U] = u30;
    uint32_t nb0 = (uint32_t)4U;
    uint8_t *b01 = d + s1 * nb0;
    uint8_t *b11 = d + s3 * nb0;
    uint8_t *b21 = d + s5 * nb0;
    uint8_t *b31 = d + s7 * nb0;
    uint32_t u4 = load32_le(b01);
    uint32_t u01 = u4;
    uint32_t u5 = load32_le(b11);
    uint32_t u110 = u5;
    uint32_t u6 = load32_le(b21);
    uint32_t u21 = u6;
    uint32_t u7 = load32_le(b31);
    uint32_t u31 = u7;
    r10[0U] = u01;
    r10[1U] = u110;
    r10[2U] = u21;
    r10[3U] = u31;
    uint32_t nb1 = (uint32_t)4U;
    uint8_t *b02 = d + s8 * nb1;
    uint8_t *b12 = d + s10 * nb1;
    uint8_t *b22 = d + s12 * nb1;
    uint8_t *b32 = d + s14 * nb1;
    uint32_t u8 = load32_le(b02);
    uint32_t u02 = u8;
    uint32_t u9 = load32_le(b12);
    uint32_t u111 = u9;
    uint32_t u10 = load32_le(b22);
    uint32_t u22 = u10;
    uint32_t u12 = load32_le(b32);
    uint32_t u32 = u12;
    r20[0U] = u02;
    r20[1U] = u111;
    r20[2U] = u22;
    r20[3U] = u32;
    uint32_t nb2 = (uint32_t)4U;
    uint8_t *b0 = d + s9 * nb2;
    uint8_t *b1 = d + s11 * nb2;
    uint8_t *b2 = d + s13 * nb2;
    uint8_t *b3 = d + s15 * nb2;
    uint32_t u13 = load32_le(b0);
    uint32_t u03 = u13;
    uint32_t u14 = load32_le(b1);
    uint32_t u112 = u14;
    uint32_t u15 = load32_le(b2);
    uint32_t u23 = u15;
    uint32_t u = load32_le(b3);
    uint32_t u33 = u;
    r30[0U] = u03;
    r30[1U] = u112;
    r30[2U] = u23;
    r30[3U] = u33;
    uint32_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint32_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint32_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint32_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b4 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_S[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_S[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_S[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_S[3U];
    uint32_t zz0[4U] = { 0U };
    uint32_t *wv_a0 = wv + a * (uint32_t)4U;
    uint32_t *wv_b0 = wv + b4 * (uint32_t)4U;
    {
      uint32_t *os = wv_a0;
      uint32_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a0;
      uint32_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a0;
      uint32_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a0;
      uint32_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint32_t *os = wv_a0;
      uint32_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a0;
      uint32_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a0;
      uint32_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a0;
      uint32_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint32_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint32_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint32_t *os = wv_a1;
      uint32_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a1;
      uint32_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a1;
      uint32_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a1;
      uint32_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint32_t *r110 = wv_a1;
    {
      uint32_t *os = r110;
      uint32_t x1 = r110[0U];
      uint32_t x10 = x1 >> r01 | x1 << ((uint32_t)32U - r01);
      os[0U] = x10;
    }
    {
      uint32_t *os = r110;
      uint32_t x1 = r110[1U];
      uint32_t x10 = x1 >> r01 | x1 << ((uint32_t)32U - r01);
      os[1U] = x10;
    }
    {
      uint32_t *os = r110;
      uint32_t x1 = r110[2U];
      uint32_t x10 = x1 >> r01 | x1 << ((uint32_t)32U - r01);
      os[2U] = x10;
    }
    {
      uint32_t *os = r110;
      uint32_t x1 = r110[3U];
      uint32_t x10 = x1 >> r01 | x1 << ((uint32_t)32U - r01);
      os[3U] = x10;
    }
    uint32_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint32_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint32_t *os = wv_a2;
      uint32_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a2;
      uint32_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a2;
      uint32_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a2;
      uint32_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    {
      uint32_t *os = wv_a2;
      uint32_t x1 = wv_a2[0U] + zz0[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a2;
      uint32_t x1 = wv_a2[1U] + zz0[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a2;
      uint32_t x1 = wv_a2[2U] + zz0[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a2;
      uint32_t x1 = wv_a2[3U] + zz0[3U];
      os[3U] = x1;
    }
    uint32_t *wv_a3 = wv + b4 * (uint32_t)4U;
    uint32_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint32_t *os = wv_a3;
      uint32_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a3;
      uint32_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a3;
      uint32_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a3;
      uint32_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint32_t *r111 = wv_a3;
    {
      uint32_t *os = r111;
      uint32_t x1 = r111[0U];
      uint32_t x10 = x1 >> r12 | x1 << ((uint32_t)32U - r12);
      os[0U] = x10;
    }
    {
      uint32_t *os = r111;
      uint32_t x1 = r111[1U];
      uint32_t x10 = x1 >> r12 | x1 << ((uint32_t)32U - r12);
      os[1U] = x10;
    }
    {
      uint32_t *os = r111;
      uint32_t x1 = r111[2U];
      uint32_t x10 = x1 >> r12 | x1 << ((uint32_t)32U - r12);
      os[2U] = x10;
    }
    {
      uint32_t *os = r111;
      uint32_t x1 = r111[3U];
      uint32_t x10 = x1 >> r12 | x1 << ((uint32_t)32U - r12);
      os[3U] = x10;
    }
    uint32_t *wv_a4 = wv + a * (uint32_t)4U;
    uint32_t *wv_b4 = wv + b4 * (uint32_t)4U;
    {
      uint32_t *os = wv_a4;
      uint32_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a4;
      uint32_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a4;
      uint32_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a4;
      uint32_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint32_t *os = wv_a4;
      uint32_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a4;
      uint32_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a4;
      uint32_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a4;
      uint32_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint32_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint32_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint32_t *os = wv_a5;
      uint32_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a5;
      uint32_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a5;
      uint32_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a5;
      uint32_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint32_t *r112 = wv_a5;
    {
      uint32_t *os = r112;
      uint32_t x1 = r112[0U];
      uint32_t x10 = x1 >> r21 | x1 << ((uint32_t)32U - r21);
      os[0U] = x10;
    }
    {
      uint32_t *os = r112;
      uint32_t x1 = r112[1U];
      uint32_t x10 = x1 >> r21 | x1 << ((uint32_t)32U - r21);
      os[1U] = x10;
    }
    {
      uint32_t *os = r112;
      uint32_t x1 = r112[2U];
      uint32_t x10 = x1 >> r21 | x1 << ((uint32_t)32U - r21);
      os[2U] = x10;
    }
    {
      uint32_t *os = r112;
      uint32_t x1 = r112[3U];
      uint32_t x10 = x1 >> r21 | x1 << ((uint32_t)32U - r21);
      os[3U] = x10;
    }
    uint32_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint32_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint32_t *os = wv_a6;
      uint32_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a6;
      uint32_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a6;
      uint32_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a6;
      uint32_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    {
      uint32_t *os = wv_a6;
      uint32_t x1 = wv_a6[0U] + zz0[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a6;
      uint32_t x1 = wv_a6[1U] + zz0[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a6;
      uint32_t x1 = wv_a6[2U] + zz0[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a6;
      uint32_t x1 = wv_a6[3U] + zz0[3U];
      os[3U] = x1;
    }
    uint32_t *wv_a7 = wv + b4 * (uint32_t)4U;
    uint32_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint32_t *os = wv_a7;
      uint32_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a7;
      uint32_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a7;
      uint32_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a7;
      uint32_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint32_t *r113 = wv_a7;
    {
      uint32_t *os = r113;
      uint32_t x1 = r113[0U];
      uint32_t x10 = x1 >> r31 | x1 << ((uint32_t)32U - r31);
      os[0U] = x10;
    }
    {
      uint32_t *os = r113;
      uint32_t x1 = r113[1U];
      uint32_t x10 = x1 >> r31 | x1 << ((uint32_t)32U - r31);
      os[1U] = x10;
    }
    {
      uint32_t *os = r113;
      uint32_t x1 = r113[2U];
      uint32_t x10 = x1 >> r31 | x1 << ((uint32_t)32U - r31);
      os[2U] = x10;
    }
    {
      uint32_t *os = r113;
      uint32_t x1 = r113[3U];
      uint32_t x10 = x1 >> r31 | x1 << ((uint32_t)32U - r31);
      os[3U] = x10;
    }
    uint32_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint32_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint32_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint32_t *r114 = r13;
    uint32_t x00 = r114[1U];
    uint32_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint32_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint32_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint32_t *r115 = r22;
    uint32_t x01 = r115[2U];
    uint32_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint32_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint32_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint32_t *r116 = r32;
    uint32_t x02 = r116[3U];
    uint32_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint32_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint32_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_S[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_S[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_S[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_S[3U];
    uint32_t zz[4U] = { 0U };
    uint32_t *wv_a = wv + a0 * (uint32_t)4U;
    uint32_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint32_t *os = wv_a;
      uint32_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a;
      uint32_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a;
      uint32_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a;
      uint32_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint32_t *os = wv_a;
      uint32_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a;
      uint32_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a;
      uint32_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a;
      uint32_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint32_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint32_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint32_t *os = wv_a8;
      uint32_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a8;
      uint32_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a8;
      uint32_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a8;
      uint32_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint32_t *r117 = wv_a8;
    {
      uint32_t *os = r117;
      uint32_t x1 = r117[0U];
      uint32_t x13 = x1 >> r0 | x1 << ((uint32_t)32U - r0);
      os[0U] = x13;
    }
    {
      uint32_t *os = r117;
      uint32_t x1 = r117[1U];
      uint32_t x13 = x1 >> r0 | x1 << ((uint32_t)32U - r0);
      os[1U] = x13;
    }
    {
      uint32_t *os = r117;
      uint32_t x1 = r117[2U];
      uint32_t x13 = x1 >> r0 | x1 << ((uint32_t)32U - r0);
      os[2U] = x13;
    }
    {
      uint32_t *os = r117;
      uint32_t x1 = r117[3U];
      uint32_t x13 = x1 >> r0 | x1 << ((uint32_t)32U - r0);
      os[3U] = x13;
    }
    uint32_t *wv_a9 = wv + c * (uint32_t)4U;
    uint32_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint32_t *os = wv_a9;
      uint32_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a9;
      uint32_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a9;
      uint32_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a9;
      uint32_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    {
      uint32_t *os = wv_a9;
      uint32_t x1 = wv_a9[0U] + zz[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a9;
      uint32_t x1 = wv_a9[1U] + zz[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a9;
      uint32_t x1 = wv_a9[2U] + zz[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a9;
      uint32_t x1 = wv_a9[3U] + zz[3U];
      os[3U] = x1;
    }
    uint32_t *wv_a10 = wv + b * (uint32_t)4U;
    uint32_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint32_t *os = wv_a10;
      uint32_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a10;
      uint32_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a10;
      uint32_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a10;
      uint32_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint32_t *r118 = wv_a10;
    {
      uint32_t *os = r118;
      uint32_t x1 = r118[0U];
      uint32_t x13 = x1 >> r1 | x1 << ((uint32_t)32U - r1);
      os[0U] = x13;
    }
    {
      uint32_t *os = r118;
      uint32_t x1 = r118[1U];
      uint32_t x13 = x1 >> r1 | x1 << ((uint32_t)32U - r1);
      os[1U] = x13;
    }
    {
      uint32_t *os = r118;
      uint32_t x1 = r118[2U];
      uint32_t x13 = x1 >> r1 | x1 << ((uint32_t)32U - r1);
      os[2U] = x13;
    }
    {
      uint32_t *os = r118;
      uint32_t x1 = r118[3U];
      uint32_t x13 = x1 >> r1 | x1 << ((uint32_t)32U - r1);
      os[3U] = x13;
    }
    uint32_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint32_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint32_t *os = wv_a11;
      uint32_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a11;
      uint32_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a11;
      uint32_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a11;
      uint32_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint32_t *os = wv_a11;
      uint32_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a11;
      uint32_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a11;
      uint32_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a11;
      uint32_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint32_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint32_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint32_t *os = wv_a12;
      uint32_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a12;
      uint32_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a12;
      uint32_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a12;
      uint32_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint32_t *r119 = wv_a12;
    {
      uint32_t *os = r119;
      uint32_t x1 = r119[0U];
      uint32_t x13 = x1 >> r23 | x1 << ((uint32_t)32U - r23);
      os[0U] = x13;
    }
    {
      uint32_t *os = r119;
      uint32_t x1 = r119[1U];
      uint32_t x13 = x1 >> r23 | x1 << ((uint32_t)32U - r23);
      os[1U] = x13;
    }
    {
      uint32_t *os = r119;
      uint32_t x1 = r119[2U];
      uint32_t x13 = x1 >> r23 | x1 << ((uint32_t)32U - r23);
      os[2U] = x13;
    }
    {
      uint32_t *os = r119;
      uint32_t x1 = r119[3U];
      uint32_t x13 = x1 >> r23 | x1 << ((uint32_t)32U - r23);
      os[3U] = x13;
    }
    uint32_t *wv_a13 = wv + c * (uint32_t)4U;
    uint32_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint32_t *os = wv_a13;
      uint32_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a13;
      uint32_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a13;
      uint32_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a13;
      uint32_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    {
      uint32_t *os = wv_a13;
      uint32_t x1 = wv_a13[0U] + zz[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a13;
      uint32_t x1 = wv_a13[1U] + zz[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a13;
      uint32_t x1 = wv_a13[2U] + zz[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a13;
      uint32_t x1 = wv_a13[3U] + zz[3U];
      os[3U] = x1;
    }
    uint32_t *wv_a14 = wv + b * (uint32_t)4U;
    uint32_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint32_t *os = wv_a14;
      uint32_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint32_t *os = wv_a14;
      uint32_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint32_t *os = wv_a14;
      uint32_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint32_t *os = wv_a14;
      uint32_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint32_t *r1110 = wv_a14;
    {
      uint32_t *os = r1110;
      uint32_t x1 = r1110[0U];
      uint32_t x13 = x1 >> r33 | x1 << ((uint32_t)32U - r33);
      os[0U] = x13;
    }
    {
      uint32_t *os = r1110;
      uint32_t x1 = r1110[1U];
      uint32_t x13 = x1 >> r33 | x1 << ((uint32_t)32U - r33);
      os[1U] = x13;
    }
    {
      uint32_t *os = r1110;
      uint32_t x1 = r1110[2U];
      uint32_t x13 = x1 >> r33 | x1 << ((uint32_t)32U - r33);
      os[2U] = x13;
    }
    {
      uint32_t *os = r1110;
      uint32_t x1 = r1110[3U];
      uint32_t x13 = x1 >> r33 | x1 << ((uint32_t)32U - r33);
      os[3U] = x13;
    }
    uint32_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint32_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint32_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint32_t *r11 = r14;
    uint32_t x03 = r11[3U];
    uint32_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint32_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint32_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint32_t *r1111 = r2;
    uint32_t x04 = r1111[2U];
    uint32_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint32_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint32_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint32_t *r1112 = r3;
    uint32_t x0 = r1112[1U];
    uint32_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint32_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint32_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  uint32_t *s0 = hash + (uint32_t)0U * (uint32_t)4U;
  uint32_t *s1 = hash + (uint32_t)1U * (uint32_t)4U;
  uint32_t *r0 = wv + (uint32_t)0U * (uint32_t)4U;
  uint32_t *r1 = wv + (uint32_t)1U * (uint32_t)4U;
  uint32_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
  uint32_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
  {
    uint32_t *os = s0;
    uint32_t x = s0[0U] ^ r0[0U];
    os[0U] = x;
  }
  {
    uint32_t *os = s0;
    uint32_t x = s0[1U] ^ r0[1U];
    os[1U] = x;
  }
  {
    uint32_t *os = s0;
    uint32_t x = s0[2U] ^ r0[2U];
    os[2U] = x;
  }
  {
    uint32_t *os = s0;
    uint32_t x = s0[3U] ^ r0[3U];
    os[3U] = x;
  }
  {
    uint32_t *os = s0;
    uint32_t x = s0[0U] ^ r2[0U];
    os[0U] = x;
  }
  {
    uint32_t *os = s0;
    uint32_t x = s0[1U] ^ r2[1U];
    os[1U] = x;
  }
  {
    uint32_t *os = s0;
    uint32_t x = s0[2U] ^ r2[2U];
    os[2U] = x;
  }
  {
    uint32_t *os = s0;
    uint32_t x = s0[3U] ^ r2[3U];
    os[3U] = x;
  }
  {
    uint32_t *os = s1;
    uint32_t x = s1[0U] ^ r1[0U];
    os[0U] = x;
  }
  {
    uint32_t *os = s1;
    uint32_t x = s1[1U] ^ r1[1U];
    os[1U] = x;
  }
  {
    uint32_t *os = s1;
    uint32_t x = s1[2U] ^ r1[2U];
    os[2U] = x;
  }
  {
    uint32_t *os = s1;
    uint32_t x = s1[3U] ^ r1[3U];
    os[3U] = x;
  }
  {
    uint32_t *os = s1;
    uint32_t x = s1[0U] ^ r3[0U];
    os[0U] = x;
  }
  {
    uint32_t *os = s1;
    uint32_t x = s1[1U] ^ r3[1U];
    os[1U] = x;
  }
  {
    uint32_t *os = s1;
    uint32_t x = s1[2U] ^ r3[2U];
    os[2U] = x;
  }
  {
    uint32_t *os = s1;
    uint32_t x = s1[3U] ^ r3[3U];
    os[3U] = x;
  }
}

void
Hacl_Blake2s_32_blake2s(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
)
{
  uint32_t stlen = (uint32_t)4U * (uint32_t)4U;
  uint32_t stzero = (uint32_t)0U;
  KRML_CHECK_SIZE(sizeof (uint32_t), stlen);
  uint32_t b[stlen];
  for (uint32_t _i = 0U; _i < stlen; ++_i)
    b[_i] = stzero;
  uint64_t prev0;
  if (kk == (uint32_t)0U)
  {
    prev0 = (uint64_t)(uint32_t)0U;
  }
  else
  {
    prev0 = (uint64_t)(uint32_t)64U;
  }
  KRML_CHECK_SIZE(sizeof (uint32_t), stlen);
  uint32_t b1[stlen];
  for (uint32_t _i = 0U; _i < stlen; ++_i)
    b1[_i] = stzero;
  uint8_t b20[64U] = { 0U };
  uint32_t *r0 = b + (uint32_t)0U * (uint32_t)4U;
  uint32_t *r1 = b + (uint32_t)1U * (uint32_t)4U;
  uint32_t *r2 = b + (uint32_t)2U * (uint32_t)4U;
  uint32_t *r3 = b + (uint32_t)3U * (uint32_t)4U;
  uint32_t iv0 = Hacl_Impl_Blake2_Constants_ivTable_S[0U];
  uint32_t iv1 = Hacl_Impl_Blake2_Constants_ivTable_S[1U];
  uint32_t iv2 = Hacl_Impl_Blake2_Constants_ivTable_S[2U];
  uint32_t iv3 = Hacl_Impl_Blake2_Constants_ivTable_S[3U];
  uint32_t iv4 = Hacl_Impl_Blake2_Constants_ivTable_S[4U];
  uint32_t iv5 = Hacl_Impl_Blake2_Constants_ivTable_S[5U];
  uint32_t iv6 = Hacl_Impl_Blake2_Constants_ivTable_S[6U];
  uint32_t iv7 = Hacl_Impl_Blake2_Constants_ivTable_S[7U];
  r2[0U] = iv0;
  r2[1U] = iv1;
  r2[2U] = iv2;
  r2[3U] = iv3;
  r3[0U] = iv4;
  r3[1U] = iv5;
  r3[2U] = iv6;
  r3[3U] = iv7;
  uint32_t kk_shift_8 = kk << (uint32_t)8U;
  uint32_t iv0_ = iv0 ^ ((uint32_t)0x01010000U ^ (kk_shift_8 ^ nn));
  r0[0U] = iv0_;
  r0[1U] = iv1;
  r0[2U] = iv2;
  r0[3U] = iv3;
  r1[0U] = iv4;
  r1[1U] = iv5;
  r1[2U] = iv6;
  r1[3U] = iv7;
  if (!(kk == (uint32_t)0U))
  {
    memcpy(b20, k, kk * sizeof (k[0U]));
    uint64_t totlen = (uint64_t)(uint32_t)0U + (uint64_t)(uint32_t)64U;
    uint8_t *b3 = b20 + (uint32_t)0U * (uint32_t)64U;
    blake2s_update_block(b1, b, false, totlen, b3);
  }
  memset(b20, 0U, (uint32_t)64U * sizeof (b20[0U]));
  uint32_t nb0 = ll / (uint32_t)64U;
  uint32_t rem10 = ll % (uint32_t)64U;
  K___uint32_t_uint32_t scrut;
  if (rem10 == (uint32_t)0U && nb0 > (uint32_t)0U)
  {
    uint32_t nb_ = nb0 - (uint32_t)1U;
    uint32_t rem_ = (uint32_t)64U;
    scrut = ((K___uint32_t_uint32_t){ .fst = nb_, .snd = rem_ });
  }
  else
  {
    scrut = ((K___uint32_t_uint32_t){ .fst = nb0, .snd = rem10 });
  }
  uint32_t nb = scrut.fst;
  uint32_t rem1 = scrut.snd;
  for (uint32_t i = (uint32_t)0U; i < nb; i++)
  {
    uint64_t totlen = prev0 + (uint64_t)((i + (uint32_t)1U) * (uint32_t)64U);
    uint8_t *b2 = d + i * (uint32_t)64U;
    blake2s_update_block(b1, b, false, totlen, b2);
  }
  uint8_t b21[64U] = { 0U };
  uint8_t *last1 = d + ll - rem1;
  memcpy(b21, last1, rem1 * sizeof (last1[0U]));
  uint64_t totlen = prev0 + (uint64_t)ll;
  blake2s_update_block(b1, b, true, totlen, b21);
  memset(b21, 0U, (uint32_t)64U * sizeof (b21[0U]));
  uint32_t double_row = (uint32_t)2U * (uint32_t)4U * (uint32_t)4U;
  KRML_CHECK_SIZE(sizeof (uint8_t), double_row);
  uint8_t b2[double_row];
  memset(b2, 0U, double_row * sizeof (b2[0U]));
  uint8_t *first = b2;
  uint8_t *second = b2 + (uint32_t)4U * (uint32_t)4U;
  uint32_t *row0 = b + (uint32_t)0U * (uint32_t)4U;
  uint32_t *row1 = b + (uint32_t)1U * (uint32_t)4U;
  {
    store32_le(first + (uint32_t)0U * (uint32_t)4U, row0[0U]);
  }
  {
    store32_le(first + (uint32_t)1U * (uint32_t)4U, row0[1U]);
  }
  {
    store32_le(first + (uint32_t)2U * (uint32_t)4U, row0[2U]);
  }
  {
    store32_le(first + (uint32_t)3U * (uint32_t)4U, row0[3U]);
  }
  {
    store32_le(second + (uint32_t)0U * (uint32_t)4U, row1[0U]);
  }
  {
    store32_le(second + (uint32_t)1U * (uint32_t)4U, row1[1U]);
  }
  {
    store32_le(second + (uint32_t)2U * (uint32_t)4U, row1[2U]);
  }
  {
    store32_le(second + (uint32_t)3U * (uint32_t)4U, row1[3U]);
  }
  uint8_t *final = b2;
  memcpy(output, final, nn * sizeof (final[0U]));
  memset(b2, 0U, double_row * sizeof (b2[0U]));
  for (uint32_t _i = 0U; _i < stlen; ++_i)
    b1[_i] = stzero;
  for (uint32_t _i = 0U; _i < stlen; ++_i)
    b[_i] = stzero;
}


void
blake2s_hacl(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
)
{
  Hacl_Blake2s_32_blake2s (nn, output, ll, d, kk, k);
}