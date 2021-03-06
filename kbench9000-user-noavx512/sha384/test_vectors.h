/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

typedef struct {
  uint8_t *input;
  size_t input_len;
  uint8_t *expected;
  size_t expected_len;
} sha384_test_vector;



uint8_t test1_plaintext[3U] = {
  0x61U, 0x62U, 0x63U
};


uint8_t test1_expected384[48] = {
      0xcbU, 0x00U, 0x75U, 0x3fU, 0x45U, 0xa3U, 0x5eU, 0x8bU,
      0xb5U, 0xa0U, 0x3dU, 0x69U, 0x9aU, 0xc6U, 0x50U, 0x07U,
      0x27U, 0x2cU, 0x32U, 0xabU, 0x0eU, 0xdeU, 0xd1U, 0x63U,
      0x1aU, 0x8bU, 0x60U, 0x5aU, 0x43U, 0xffU, 0x5bU, 0xedU,
      0x80U, 0x86U, 0x07U, 0x2bU, 0xa1U, 0xe7U, 0xccU, 0x23U,
      0x58U, 0xbaU, 0xecU, 0xa1U, 0x34U, 0xc8U, 0x25U, 0xa7U  
};



static sha384_test_vector vectors_sha384[] = {
  {
    .input = test1_plaintext,
    .input_len = sizeof(test1_plaintext)/sizeof(uint8_t),
    .expected = test1_expected384,
    .expected_len = sizeof(test1_expected384)/sizeof(uint8_t),
  }
};
