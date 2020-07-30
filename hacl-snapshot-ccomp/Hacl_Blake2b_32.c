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


#include "Hacl_Blake2b_32.h"

static inline void
blake2b_update_block(
  uint64_t *wv,
  uint64_t *hash,
  bool flag,
  FStar_UInt128_uint128 totlen,
  uint8_t *d
)
{
  uint64_t m_w[16U] = { 0U };
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)0U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[0U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)1U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[1U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)2U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[2U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)3U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[3U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)4U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[4U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)5U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[5U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)6U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[6U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)7U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[7U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)8U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[8U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)9U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[9U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)10U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[10U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)11U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[11U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)12U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[12U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)13U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[13U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)14U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[14U] = x;
  }
  {
    uint64_t *os = m_w;
    uint8_t *bj = d + (uint32_t)15U * (uint32_t)8U;
    uint64_t u = load64_le(bj);
    uint64_t r = u;
    uint64_t x = r;
    os[15U] = x;
  }
  uint64_t mask[4U] = { 0U };
  uint64_t wv_14;
  if (flag)
  {
    wv_14 = (uint64_t)0xFFFFFFFFFFFFFFFFU;
  }
  else
  {
    wv_14 = (uint64_t)0U;
  }
  uint64_t wv_15 = (uint64_t)0U;
  mask[0U] = FStar_UInt128_uint128_to_uint64(totlen);
  mask[1U] = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(totlen, (uint32_t)64U));
  mask[2U] = wv_14;
  mask[3U] = wv_15;
  memcpy(wv, hash, (uint32_t)4U * (uint32_t)4U * sizeof (hash[0U]));
  uint64_t *wv3 = wv + (uint32_t)3U * (uint32_t)4U;
  {
    uint64_t *os = wv3;
    uint64_t x = wv3[0U] ^ mask[0U];
    os[0U] = x;
  }
  {
    uint64_t *os = wv3;
    uint64_t x = wv3[1U] ^ mask[1U];
    os[1U] = x;
  }
  {
    uint64_t *os = wv3;
    uint64_t x = wv3[2U] ^ mask[2U];
    os[2U] = x;
  }
  {
    uint64_t *os = wv3;
    uint64_t x = wv3[3U] ^ mask[3U];
    os[3U] = x;
  }
  {
    uint32_t start_idx = (uint32_t)0U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)1U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)2U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)3U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)4U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)5U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)6U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)7U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)8U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)9U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)10U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  {
    uint32_t start_idx = (uint32_t)11U % (uint32_t)10U * (uint32_t)16U;
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
    memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (m_st[0U]));
    uint64_t *r00 = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *r10 = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r20 = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r30 = m_st + (uint32_t)3U * (uint32_t)4U;
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
    uint64_t uu____0 = m_w[s2];
    uint64_t uu____1 = m_w[s4];
    uint64_t uu____2 = m_w[s6];
    r00[0U] = m_w[s0];
    r00[1U] = uu____0;
    r00[2U] = uu____1;
    r00[3U] = uu____2;
    uint64_t uu____3 = m_w[s3];
    uint64_t uu____4 = m_w[s5];
    uint64_t uu____5 = m_w[s7];
    r10[0U] = m_w[s1];
    r10[1U] = uu____3;
    r10[2U] = uu____4;
    r10[3U] = uu____5;
    uint64_t uu____6 = m_w[s10];
    uint64_t uu____7 = m_w[s12];
    uint64_t uu____8 = m_w[s14];
    r20[0U] = m_w[s8];
    r20[1U] = uu____6;
    r20[2U] = uu____7;
    r20[3U] = uu____8;
    uint64_t uu____9 = m_w[s11];
    uint64_t uu____10 = m_w[s13];
    uint64_t uu____11 = m_w[s15];
    r30[0U] = m_w[s9];
    r30[1U] = uu____9;
    r30[2U] = uu____10;
    r30[3U] = uu____11;
    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
    uint32_t a = (uint32_t)0U;
    uint32_t b0 = (uint32_t)1U;
    uint32_t c0 = (uint32_t)2U;
    uint32_t d10 = (uint32_t)3U;
    uint32_t r01 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r12 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r21 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r31 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + wv_b0[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + wv_b0[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + wv_b0[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + wv_b0[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[0U] + x[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[1U] + x[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[2U] + x[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a0;
      uint64_t x1 = wv_a0[3U] + x[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a1 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b1 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[0U] ^ wv_b1[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[1U] ^ wv_b1[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[2U] ^ wv_b1[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a1;
      uint64_t x1 = wv_a1[3U] ^ wv_b1[3U];
      os[3U] = x1;
    }
    uint64_t *r110 = wv_a1;
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[0U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[0U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[1U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[1U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[2U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[2U] = x10;
    }
    {
      uint64_t *os = r110;
      uint64_t x1 = r110[3U];
      uint64_t x10 = x1 >> r01 | x1 << ((uint32_t)64U - r01);
      os[3U] = x10;
    }
    uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b2 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[0U] + wv_b2[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[1U] + wv_b2[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[2U] + wv_b2[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a2;
      uint64_t x1 = wv_a2[3U] + wv_b2[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[0U] ^ wv_b3[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[1U] ^ wv_b3[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[2U] ^ wv_b3[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a3;
      uint64_t x1 = wv_a3[3U] ^ wv_b3[3U];
      os[3U] = x1;
    }
    uint64_t *r111 = wv_a3;
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[0U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[0U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[1U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[1U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[2U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[2U] = x10;
    }
    {
      uint64_t *os = r111;
      uint64_t x1 = r111[3U];
      uint64_t x10 = x1 >> r12 | x1 << ((uint32_t)64U - r12);
      os[3U] = x10;
    }
    uint64_t *wv_a4 = wv + a * (uint32_t)4U;
    uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + wv_b4[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + wv_b4[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + wv_b4[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + wv_b4[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[0U] + y[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[1U] + y[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[2U] + y[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a4;
      uint64_t x1 = wv_a4[3U] + y[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a5 = wv + d10 * (uint32_t)4U;
    uint64_t *wv_b5 = wv + a * (uint32_t)4U;
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[0U] ^ wv_b5[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[1U] ^ wv_b5[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[2U] ^ wv_b5[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a5;
      uint64_t x1 = wv_a5[3U] ^ wv_b5[3U];
      os[3U] = x1;
    }
    uint64_t *r112 = wv_a5;
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[0U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[0U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[1U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[1U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[2U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[2U] = x10;
    }
    {
      uint64_t *os = r112;
      uint64_t x1 = r112[3U];
      uint64_t x10 = x1 >> r21 | x1 << ((uint32_t)64U - r21);
      os[3U] = x10;
    }
    uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
    uint64_t *wv_b6 = wv + d10 * (uint32_t)4U;
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[0U] + wv_b6[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[1U] + wv_b6[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[2U] + wv_b6[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a6;
      uint64_t x1 = wv_a6[3U] + wv_b6[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
    uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[0U] ^ wv_b7[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[1U] ^ wv_b7[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[2U] ^ wv_b7[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a7;
      uint64_t x1 = wv_a7[3U] ^ wv_b7[3U];
      os[3U] = x1;
    }
    uint64_t *r113 = wv_a7;
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[0U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[0U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[1U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[1U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[2U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[2U] = x10;
    }
    {
      uint64_t *os = r113;
      uint64_t x1 = r113[3U];
      uint64_t x10 = x1 >> r31 | x1 << ((uint32_t)64U - r31);
      os[3U] = x10;
    }
    uint64_t *r13 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r114 = r13;
    uint64_t x00 = r114[1U];
    uint64_t x10 = r114[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x20 = r114[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x30 = r114[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r114[0U] = x00;
    r114[1U] = x10;
    r114[2U] = x20;
    r114[3U] = x30;
    uint64_t *r115 = r22;
    uint64_t x01 = r115[2U];
    uint64_t x11 = r115[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x21 = r115[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x31 = r115[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r115[0U] = x01;
    r115[1U] = x11;
    r115[2U] = x21;
    r115[3U] = x31;
    uint64_t *r116 = r32;
    uint64_t x02 = r116[3U];
    uint64_t x12 = r116[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x22 = r116[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x32 = r116[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r116[0U] = x02;
    r116[1U] = x12;
    r116[2U] = x22;
    r116[3U] = x32;
    uint32_t a0 = (uint32_t)0U;
    uint32_t b = (uint32_t)1U;
    uint32_t c = (uint32_t)2U;
    uint32_t d1 = (uint32_t)3U;
    uint32_t r0 = Hacl_Impl_Blake2_Constants_rTable_B[0U];
    uint32_t r1 = Hacl_Impl_Blake2_Constants_rTable_B[1U];
    uint32_t r23 = Hacl_Impl_Blake2_Constants_rTable_B[2U];
    uint32_t r33 = Hacl_Impl_Blake2_Constants_rTable_B[3U];
    uint64_t *wv_a = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b8 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + wv_b8[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + wv_b8[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + wv_b8[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + wv_b8[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[0U] + z[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[1U] + z[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[2U] + z[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a;
      uint64_t x1 = wv_a[3U] + z[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a8 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[0U] ^ wv_b9[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[1U] ^ wv_b9[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[2U] ^ wv_b9[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a8;
      uint64_t x1 = wv_a8[3U] ^ wv_b9[3U];
      os[3U] = x1;
    }
    uint64_t *r117 = wv_a8;
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[0U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[0U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[1U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[1U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[2U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[2U] = x13;
    }
    {
      uint64_t *os = r117;
      uint64_t x1 = r117[3U];
      uint64_t x13 = x1 >> r0 | x1 << ((uint32_t)64U - r0);
      os[3U] = x13;
    }
    uint64_t *wv_a9 = wv + c * (uint32_t)4U;
    uint64_t *wv_b10 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[0U] + wv_b10[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[1U] + wv_b10[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[2U] + wv_b10[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a9;
      uint64_t x1 = wv_a9[3U] + wv_b10[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a10 = wv + b * (uint32_t)4U;
    uint64_t *wv_b11 = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[0U] ^ wv_b11[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[1U] ^ wv_b11[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[2U] ^ wv_b11[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a10;
      uint64_t x1 = wv_a10[3U] ^ wv_b11[3U];
      os[3U] = x1;
    }
    uint64_t *r118 = wv_a10;
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[0U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[0U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[1U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[1U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[2U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[2U] = x13;
    }
    {
      uint64_t *os = r118;
      uint64_t x1 = r118[3U];
      uint64_t x13 = x1 >> r1 | x1 << ((uint32_t)64U - r1);
      os[3U] = x13;
    }
    uint64_t *wv_a11 = wv + a0 * (uint32_t)4U;
    uint64_t *wv_b12 = wv + b * (uint32_t)4U;
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + wv_b12[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + wv_b12[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + wv_b12[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + wv_b12[3U];
      os[3U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[0U] + w[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[1U] + w[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[2U] + w[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a11;
      uint64_t x1 = wv_a11[3U] + w[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a12 = wv + d1 * (uint32_t)4U;
    uint64_t *wv_b13 = wv + a0 * (uint32_t)4U;
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[0U] ^ wv_b13[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[1U] ^ wv_b13[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[2U] ^ wv_b13[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a12;
      uint64_t x1 = wv_a12[3U] ^ wv_b13[3U];
      os[3U] = x1;
    }
    uint64_t *r119 = wv_a12;
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[0U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[0U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[1U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[1U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[2U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[2U] = x13;
    }
    {
      uint64_t *os = r119;
      uint64_t x1 = r119[3U];
      uint64_t x13 = x1 >> r23 | x1 << ((uint32_t)64U - r23);
      os[3U] = x13;
    }
    uint64_t *wv_a13 = wv + c * (uint32_t)4U;
    uint64_t *wv_b14 = wv + d1 * (uint32_t)4U;
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[0U] + wv_b14[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[1U] + wv_b14[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[2U] + wv_b14[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a13;
      uint64_t x1 = wv_a13[3U] + wv_b14[3U];
      os[3U] = x1;
    }
    uint64_t *wv_a14 = wv + b * (uint32_t)4U;
    uint64_t *wv_b = wv + c * (uint32_t)4U;
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[0U] ^ wv_b[0U];
      os[0U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[1U] ^ wv_b[1U];
      os[1U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[2U] ^ wv_b[2U];
      os[2U] = x1;
    }
    {
      uint64_t *os = wv_a14;
      uint64_t x1 = wv_a14[3U] ^ wv_b[3U];
      os[3U] = x1;
    }
    uint64_t *r1110 = wv_a14;
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[0U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[0U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[1U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[1U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[2U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[2U] = x13;
    }
    {
      uint64_t *os = r1110;
      uint64_t x1 = r1110[3U];
      uint64_t x13 = x1 >> r33 | x1 << ((uint32_t)64U - r33);
      os[3U] = x13;
    }
    uint64_t *r14 = wv + (uint32_t)1U * (uint32_t)4U;
    uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
    uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
    uint64_t *r11 = r14;
    uint64_t x03 = r11[3U];
    uint64_t x13 = r11[((uint32_t)3U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x23 = r11[((uint32_t)3U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x33 = r11[((uint32_t)3U + (uint32_t)3U) % (uint32_t)4U];
    r11[0U] = x03;
    r11[1U] = x13;
    r11[2U] = x23;
    r11[3U] = x33;
    uint64_t *r1111 = r2;
    uint64_t x04 = r1111[2U];
    uint64_t x14 = r1111[((uint32_t)2U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x24 = r1111[((uint32_t)2U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x34 = r1111[((uint32_t)2U + (uint32_t)3U) % (uint32_t)4U];
    r1111[0U] = x04;
    r1111[1U] = x14;
    r1111[2U] = x24;
    r1111[3U] = x34;
    uint64_t *r1112 = r3;
    uint64_t x0 = r1112[1U];
    uint64_t x1 = r1112[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
    uint64_t x2 = r1112[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
    uint64_t x3 = r1112[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
    r1112[0U] = x0;
    r1112[1U] = x1;
    r1112[2U] = x2;
    r1112[3U] = x3;
  }
  uint64_t *s0 = hash + (uint32_t)0U * (uint32_t)4U;
  uint64_t *s1 = hash + (uint32_t)1U * (uint32_t)4U;
  uint64_t *r0 = wv + (uint32_t)0U * (uint32_t)4U;
  uint64_t *r1 = wv + (uint32_t)1U * (uint32_t)4U;
  uint64_t *r2 = wv + (uint32_t)2U * (uint32_t)4U;
  uint64_t *r3 = wv + (uint32_t)3U * (uint32_t)4U;
  {
    uint64_t *os = s0;
    uint64_t x = s0[0U] ^ r0[0U];
    os[0U] = x;
  }
  {
    uint64_t *os = s0;
    uint64_t x = s0[1U] ^ r0[1U];
    os[1U] = x;
  }
  {
    uint64_t *os = s0;
    uint64_t x = s0[2U] ^ r0[2U];
    os[2U] = x;
  }
  {
    uint64_t *os = s0;
    uint64_t x = s0[3U] ^ r0[3U];
    os[3U] = x;
  }
  {
    uint64_t *os = s0;
    uint64_t x = s0[0U] ^ r2[0U];
    os[0U] = x;
  }
  {
    uint64_t *os = s0;
    uint64_t x = s0[1U] ^ r2[1U];
    os[1U] = x;
  }
  {
    uint64_t *os = s0;
    uint64_t x = s0[2U] ^ r2[2U];
    os[2U] = x;
  }
  {
    uint64_t *os = s0;
    uint64_t x = s0[3U] ^ r2[3U];
    os[3U] = x;
  }
  {
    uint64_t *os = s1;
    uint64_t x = s1[0U] ^ r1[0U];
    os[0U] = x;
  }
  {
    uint64_t *os = s1;
    uint64_t x = s1[1U] ^ r1[1U];
    os[1U] = x;
  }
  {
    uint64_t *os = s1;
    uint64_t x = s1[2U] ^ r1[2U];
    os[2U] = x;
  }
  {
    uint64_t *os = s1;
    uint64_t x = s1[3U] ^ r1[3U];
    os[3U] = x;
  }
  {
    uint64_t *os = s1;
    uint64_t x = s1[0U] ^ r3[0U];
    os[0U] = x;
  }
  {
    uint64_t *os = s1;
    uint64_t x = s1[1U] ^ r3[1U];
    os[1U] = x;
  }
  {
    uint64_t *os = s1;
    uint64_t x = s1[2U] ^ r3[2U];
    os[2U] = x;
  }
  {
    uint64_t *os = s1;
    uint64_t x = s1[3U] ^ r3[3U];
    os[3U] = x;
  }
}

void
Hacl_Blake2b_32_blake2b(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
)
{
  uint32_t stlen = (uint32_t)4U * (uint32_t)4U;
  uint64_t stzero = (uint64_t)0U;
  KRML_CHECK_SIZE(sizeof (uint64_t), stlen);
  uint64_t b[16];
  for (uint32_t _i = 0U; _i < stlen; ++_i)
    b[_i] = stzero;
  FStar_UInt128_uint128 prev0;
  if (kk == (uint32_t)0U)
  {
    prev0 = FStar_UInt128_uint64_to_uint128((uint64_t)(uint32_t)0U);
  }
  else
  {
    prev0 = FStar_UInt128_uint64_to_uint128((uint64_t)(uint32_t)128U);
  }
  KRML_CHECK_SIZE(sizeof (uint64_t), stlen);
  uint64_t b1[16];
  for (uint32_t _i = 0U; _i < stlen; ++_i)
    b1[_i] = stzero;
  uint8_t b20[128U] = { 0U };
  uint64_t *r0 = b + (uint32_t)0U * (uint32_t)4U;
  uint64_t *r1 = b + (uint32_t)1U * (uint32_t)4U;
  uint64_t *r2 = b + (uint32_t)2U * (uint32_t)4U;
  uint64_t *r3 = b + (uint32_t)3U * (uint32_t)4U;
  uint64_t iv0 = Hacl_Impl_Blake2_Constants_ivTable_B[0U];
  uint64_t iv1 = Hacl_Impl_Blake2_Constants_ivTable_B[1U];
  uint64_t iv2 = Hacl_Impl_Blake2_Constants_ivTable_B[2U];
  uint64_t iv3 = Hacl_Impl_Blake2_Constants_ivTable_B[3U];
  uint64_t iv4 = Hacl_Impl_Blake2_Constants_ivTable_B[4U];
  uint64_t iv5 = Hacl_Impl_Blake2_Constants_ivTable_B[5U];
  uint64_t iv6 = Hacl_Impl_Blake2_Constants_ivTable_B[6U];
  uint64_t iv7 = Hacl_Impl_Blake2_Constants_ivTable_B[7U];
  r2[0U] = iv0;
  r2[1U] = iv1;
  r2[2U] = iv2;
  r2[3U] = iv3;
  r3[0U] = iv4;
  r3[1U] = iv5;
  r3[2U] = iv6;
  r3[3U] = iv7;
  uint64_t kk_shift_8 = (uint64_t)kk << (uint32_t)8U;
  uint64_t iv0_ = iv0 ^ ((uint64_t)0x01010000U ^ (kk_shift_8 ^ (uint64_t)nn));
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
    FStar_UInt128_uint128
    totlen =
      FStar_UInt128_add_mod(FStar_UInt128_uint64_to_uint128((uint64_t)(uint32_t)0U),
        FStar_UInt128_uint64_to_uint128((uint64_t)(uint32_t)128U));
    uint8_t *b3 = b20 + (uint32_t)0U * (uint32_t)128U;
    blake2b_update_block(b1, b, false, totlen, b3);
  }
  memset(b20, 0U, (uint32_t)128U * sizeof (b20[0U]));
  uint32_t nb0 = ll / (uint32_t)128U;
  uint32_t rem0 = ll % (uint32_t)128U;
  K___uint32_t_uint32_t scrut;
  if (rem0 == (uint32_t)0U && nb0 > (uint32_t)0U)
  {
    uint32_t nb_ = nb0 - (uint32_t)1U;
    uint32_t rem_ = (uint32_t)128U;
    scrut = ((K___uint32_t_uint32_t){ .fst = nb_, .snd = rem_ });
  }
  else
  {
    scrut = ((K___uint32_t_uint32_t){ .fst = nb0, .snd = rem0 });
  }
  uint32_t nb = scrut.fst;
  uint32_t rem = scrut.snd;
  for (uint32_t i = (uint32_t)0U; i < nb; i++)
  {
    FStar_UInt128_uint128
    totlen =
      FStar_UInt128_add_mod(prev0,
        FStar_UInt128_uint64_to_uint128((uint64_t)((i + (uint32_t)1U) * (uint32_t)128U)));
    uint8_t *b2 = d + i * (uint32_t)128U;
    blake2b_update_block(b1, b, false, totlen, b2);
  }
  uint8_t b21[128U] = { 0U };
  uint8_t *last = d + ll - rem;
  memcpy(b21, last, rem * sizeof (last[0U]));
  FStar_UInt128_uint128
  totlen = FStar_UInt128_add_mod(prev0, FStar_UInt128_uint64_to_uint128((uint64_t)ll));
  blake2b_update_block(b1, b, true, totlen, b21);
  memset(b21, 0U, (uint32_t)128U * sizeof (b21[0U]));
  uint32_t double_row = (uint32_t)2U * (uint32_t)4U * (uint32_t)8U;
  KRML_CHECK_SIZE(sizeof (uint8_t), double_row);
  uint8_t b2[64];
  memset(b2, 0U, double_row * sizeof (b2[0U]));
  uint8_t *first = b2;
  uint8_t *second = b2 + (uint32_t)4U * (uint32_t)8U;
  uint64_t *row0 = b + (uint32_t)0U * (uint32_t)4U;
  uint64_t *row1 = b + (uint32_t)1U * (uint32_t)4U;
  {
    store64_le(first + (uint32_t)0U * (uint32_t)8U, row0[0U]);
  }
  {
    store64_le(first + (uint32_t)1U * (uint32_t)8U, row0[1U]);
  }
  {
    store64_le(first + (uint32_t)2U * (uint32_t)8U, row0[2U]);
  }
  {
    store64_le(first + (uint32_t)3U * (uint32_t)8U, row0[3U]);
  }
  {
    store64_le(second + (uint32_t)0U * (uint32_t)8U, row1[0U]);
  }
  {
    store64_le(second + (uint32_t)1U * (uint32_t)8U, row1[1U]);
  }
  {
    store64_le(second + (uint32_t)2U * (uint32_t)8U, row1[2U]);
  }
  {
    store64_le(second + (uint32_t)3U * (uint32_t)8U, row1[3U]);
  }
  uint8_t *final = b2;
  memcpy(output, final, nn * sizeof (final[0U]));
  memset(b2, 0U, double_row * sizeof (b2[0U]));
  for (uint32_t _i = 0U; _i < stlen; ++_i)
    b1[_i] = stzero;
  for (uint32_t _i = 0U; _i < stlen; ++_i)
    b[_i] = stzero;
}

