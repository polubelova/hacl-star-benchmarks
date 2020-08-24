/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

typedef struct {
  uint8_t *input;
  size_t input_len;
  uint8_t *expected;
  size_t expected_len;
} sha224_test_vector;



uint8_t test1_plaintext[3U] = {
  0x61U, 0x62U, 0x63U
};


uint8_t test1_expected224[28] = {
  0x23U, 0x09U, 0x7dU, 0x22U, 0x34U, 0x05U, 0xd8U, 0x22U,
  0x86U, 0x42U, 0xa4U, 0x77U, 0xbdU, 0xa2U, 0x55U, 0xb3U,
  0x2aU, 0xadU, 0xbcU, 0xe4U, 0xbdU, 0xa0U, 0xb3U, 0xf7U,
  0xe3U, 0x6cU, 0x9dU, 0xa7U
};



static sha224_test_vector vectors_sha224[] = {
  {
    .input = test1_plaintext,
    .input_len = sizeof(test1_plaintext)/sizeof(uint8_t),
    .expected = test1_expected224,
    .expected_len = sizeof(test1_expected224)/sizeof(uint8_t),
  }
};
