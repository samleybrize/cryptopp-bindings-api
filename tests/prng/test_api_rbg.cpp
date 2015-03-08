/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/prng/api_rbg.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(RandomByteGeneratorTest, inheritance) {
    CryptoppApi::RandomByteGenerator rbg;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::RandomByteGeneratorInterface*>(&rbg));
}

TEST(RandomByteGeneratorTest, testGenerate) {
    CryptoppApi::RandomByteGenerator rbg;
    byte output1[5];
    byte output2[5];
    byte output3[8];
    byte *output4 = new byte[10485760];

    rbg.generate(output1, 5);
    rbg.generate(output2, 5);
    rbg.generate(output3, 8);
    rbg.generate(output4, 10485760);

    EXPECT_BYTE_ARRAY_NE(output1, sizeof(output1), output2, sizeof(output2));

    delete[] output4;
}

TEST(RandomByteGeneratorTest, testGenerateZero) {
    CryptoppApi::RandomByteGenerator rbg;
    EXPECT_THROW(rbg.generate(NULL, 0), CryptoppApi::Exception*);
}
