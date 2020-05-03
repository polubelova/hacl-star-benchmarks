/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

typedef struct {
  uint8_t *input;
  size_t input_len;
  uint8_t *key;
  size_t key_len;
  uint8_t *expected;
  size_t expected_len;
} blake2_test_vector;


static uint8_t input2b1[44] = {
  0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
  0x08U, 0x09U, 0x0aU, 0x0bU, 0x0cU, 0x0dU, 0x0eU, 0x0fU,
  0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
  0x18U, 0x19U, 0x1aU, 0x1bU, 0x1cU, 0x1dU, 0x1eU, 0x1fU,
  0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U,
  0x28U, 0x29U, 0x2aU, 0x2bU
};

static uint8_t key2b1[0] = {0
};

static uint8_t expected2b1[64] = {
  0xc7, 0x4a, 0x77, 0x39, 0x5f, 0xb8, 0xbc, 0x12,
  0x64, 0x47, 0x45, 0x48, 0x38, 0xe5, 0x61, 0xe9, 
  0x62, 0x85, 0x3d, 0xc7, 0xeb, 0x49, 0xa1, 0xe3,
  0xcb, 0x67, 0xc3, 0xd0, 0x85, 0x1f, 0x3e, 0x39,
  0x51, 0x7b, 0xe8, 0xc3, 0x50, 0xac, 0x91, 0x9,
  0x3,  0xd4, 0x9c, 0xd2, 0xbf, 0xdf, 0x54, 0x5c,
  0x99 ,0x31, 0x6d, 0x3,  0x46, 0x17, 0xb,  0x73,
  0x9f, 0xa,  0xdd, 0x5d, 0x53, 0x3c, 0x2c, 0xfc
};




static blake2_test_vector vectors2b[] = {
  {
    .input = input2b1,
    .input_len = sizeof(input2b1)/sizeof(uint8_t),
    .key = key2b1,
    .key_len = 0,
    .expected = expected2b1,
    .expected_len = sizeof(expected2b1)/sizeof(uint8_t),
  }
};