/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef TEST_API_CRYPTOPP_ASSERTIONS_H
#define TEST_API_CRYPTOPP_ASSERTIONS_H

#include "src/api_cryptopp.h"
#include <gtest/gtest.h>

#define EXPECT_BYTE_ARRAY_EQ(expected, expectedSize, actual, actualSize) GTEST_ASSERT_(ByteArrayEquals(expected, expectedSize, actual, actualSize), GTEST_NONFATAL_FAILURE_);
#define ASSERT_BYTE_ARRAY_EQ(expected, expectedSize, actual, actualSize) GTEST_ASSERT_(ByteArrayEquals(expected, expectedSize, actual, actualSize), GTEST_FATAL_FAILURE_);

::testing::AssertionResult ByteArrayEquals(byte *expected, size_t expectedSize, byte *actual, size_t actualSize);

void hex2bin(const char *input, size_t inputLength, byte **output, size_t &outputLength);

#endif /* TEST_API_CRYPTOPP_ASSERTIONS_H */
