#include "types.h"
#include "kremlin/lowstar_endianness.h"
#include <string.h>
// #include "lib_intrinsics.h"

#ifndef __Hacl_Kremlib_H
#define __Hacl_Kremlib_H



static inline uint64_t FStar_UInt64_eq_mask(uint64_t a, uint64_t b);

static inline uint64_t FStar_UInt64_gte_mask(uint64_t a, uint64_t b);

static inline uint8_t FStar_UInt8_eq_mask(uint8_t a, uint8_t b);

static inline FStar_UInt128_uint128
FStar_UInt128_add(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b);

static inline FStar_UInt128_uint128
FStar_UInt128_shift_left(FStar_UInt128_uint128 a, uint32_t s);

static inline FStar_UInt128_uint128
FStar_UInt128_shift_right(FStar_UInt128_uint128 a, uint32_t s);

static inline FStar_UInt128_uint128 FStar_UInt128_uint64_to_uint128(uint64_t a);

static inline uint64_t FStar_UInt128_uint128_to_uint64(FStar_UInt128_uint128 a);

static inline FStar_UInt128_uint128 FStar_UInt128_mul_wide(uint64_t x, uint64_t y);

static inline void store128_be(uint8_t *x0, FStar_UInt128_uint128 x1);

extern void C_String_print(C_String_t uu____147);

extern void LowStar_Printf_print_string(Prims_string uu____92);

extern void LowStar_Printf_print_u32(uint32_t uu____140);

extern void LowStar_Printf_print_lmbuffer_u8(uint32_t l, uint8_t *r);

#define __Hacl_Kremlib_H_DEFINED
#endif
