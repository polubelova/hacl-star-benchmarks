#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;
typedef __uint128_t uint128_t;

//#define load_limb(b_i) le64_to_cpup((__force __le64 *)b_i)
//#define store_limb(b_o,o) *(__force __le64 *)(b_o) = cpu_to_le64(o)

inline u64 load64_le(const u8* b){
  uint64_t x;
  memcpy(&x, b, 8);
  return x;
}
inline void store64_le(u8* b,u64 o) {
  memcpy(b,&o,8);
}

inline u64 load32_le(const u8* b){
  uint32_t x;
  memcpy(&x, b, 4);
  return x;
}
inline void store32_le(u64 o, u8* b) {
  memcpy(b,&o,4);
}

#define KRML_CHECK_SIZE(a,b) {}
//#define __always_inline inline
#define __aligned(x) __attribute__((aligned(x)))

__always_inline static uint64_t FStar_UInt64_eq_mask(uint64_t a, uint64_t b)
{
  uint64_t x = a ^ b;
  uint64_t minus_x = ~x + (uint64_t)1U;
  uint64_t x_or_minus_x = x | minus_x;
  uint64_t xnx = x_or_minus_x >> (uint32_t)63U;
  return xnx - (uint64_t)1U;
}

__always_inline static uint64_t FStar_UInt64_gte_mask(uint64_t a, uint64_t b)
{
  uint64_t x = a;
  uint64_t y = b;
  uint64_t x_xor_y = x ^ y;
  uint64_t x_sub_y = x - y;
  uint64_t x_sub_y_xor_y = x_sub_y ^ y;
  uint64_t q = x_xor_y | x_sub_y_xor_y;
  uint64_t x_xor_q = x ^ q;
  uint64_t x_xor_q_ = x_xor_q >> (uint32_t)63U;
  return x_xor_q_ - (uint64_t)1U;
}

