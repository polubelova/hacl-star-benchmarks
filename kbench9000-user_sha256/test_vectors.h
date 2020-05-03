/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

typedef struct {
  uint8_t *input;
  size_t input_len;
  uint8_t *expected;
  size_t expected_len;
} blake2_test_vector;



uint8_t test1_plaintext[3U] = {
  0x61U, 0x62U, 0x63U
};


uint8_t test1_expected256[32] = {
  0xbaU, 0x78U, 0x16U, 0xbfU, 0x8fU, 0x01U, 0xcfU, 0xeaU,
  0x41U, 0x41U, 0x40U, 0xdeU, 0x5dU, 0xaeU, 0x22U, 0x23U,
  0xb0U, 0x03U, 0x61U, 0xa3U, 0x96U, 0x17U, 0x7aU, 0x9cU,
  0xb4U, 0x10U, 0xffU, 0x61U, 0xf2U, 0x00U, 0x15U, 0xadU
};



static blake2_test_vector vectors2b[] = {
  {
    .input = test1_plaintext,
    .input_len = sizeof(test1_plaintext)/sizeof(uint8_t),
    .expected = test1_expected256,
    .expected_len = sizeof(test1_expected256)/sizeof(uint8_t),
  }
};