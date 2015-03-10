/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/padding/api_padding_no_padding.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>
#include <string>

TEST(PaddingNoPaddingTest, inheritance) {
    CryptoppApi::PaddingNoPadding padding;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::PaddingInterface*>(&padding));
}

TEST(PaddingNoPaddingTest, testPad) {
    CryptoppApi::PaddingNoPadding padding;

    std::string input1Str("azerty");
    std::string input2Str("qwerty");
    const byte *input1 = reinterpret_cast<const byte*>(input1Str.c_str());
    const byte *input2 = reinterpret_cast<const byte*>(input2Str.c_str());

    byte *output1;
    byte *output2;
    size_t output1Length = 0;
    size_t output2Length = 0;
    padding.pad(6, input1, input1Str.length(), &output1, output1Length);
    padding.pad(8, input2, input2Str.length(), &output2, output2Length);

    EXPECT_BYTE_ARRAY_EQ(input1, input1Str.length(), output1, output1Length);
    EXPECT_BYTE_ARRAY_EQ(input2, input2Str.length(), output2, output2Length);

    delete[] output1;
    delete[] output2;
}

TEST(PaddingNoPaddingTest, testUnpad) {
    CryptoppApi::PaddingNoPadding padding;

    std::string input1Str("wxcvbn");
    std::string input2Str("qscvbn");
    const byte *input1 = reinterpret_cast<const byte*>(input1Str.c_str());
    const byte *input2 = reinterpret_cast<const byte*>(input2Str.c_str());

    byte *output1;
    byte *output2;
    size_t output1Length = 0;
    size_t output2Length = 0;
    padding.unpad(6, input1, input1Str.length(), &output1, output1Length);
    padding.unpad(8, input2, input2Str.length(), &output2, output2Length);

    EXPECT_BYTE_ARRAY_EQ(input1, input1Str.length(), output1, output1Length);
    EXPECT_BYTE_ARRAY_EQ(input2, input2Str.length(), output2, output2Length);

    delete[] output1;
    delete[] output2;
}

TEST(PaddingNoPaddingTest, testCan) {
    CryptoppApi::PaddingNoPadding padding;
    EXPECT_FALSE(padding.canPad());
    EXPECT_FALSE(padding.canUnpad());
}

// TODO large
