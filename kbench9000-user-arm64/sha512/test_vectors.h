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


uint8_t test1_expected512[64] = {
      0xddU, 0xafU, 0x35U, 0xa1U, 0x93U, 0x61U, 0x7aU, 0xbaU,
      0xccU, 0x41U, 0x73U, 0x49U, 0xaeU, 0x20U, 0x41U, 0x31U,
      0x12U, 0xe6U, 0xfaU, 0x4eU, 0x89U, 0xa9U, 0x7eU, 0xa2U,
      0x0aU, 0x9eU, 0xeeU, 0xe6U, 0x4bU, 0x55U, 0xd3U, 0x9aU,
      0x21U, 0x92U, 0x99U, 0x2aU, 0x27U, 0x4fU, 0xc1U, 0xa8U,
      0x36U, 0xbaU, 0x3cU, 0x23U, 0xa3U, 0xfeU, 0xebU, 0xbdU,
      0x45U, 0x4dU, 0x44U, 0x23U, 0x64U, 0x3cU, 0xe8U, 0x0eU,
      0x2aU, 0x9aU, 0xc9U, 0x4fU, 0xa5U, 0x4cU, 0xa4U, 0x9fU
};



static blake2_test_vector vectors2b[] = {
  {
    .input = test1_plaintext,
    .input_len = sizeof(test1_plaintext)/sizeof(uint8_t),
    .expected = test1_expected512,
    .expected_len = sizeof(test1_expected512)/sizeof(uint8_t),
  }
};
