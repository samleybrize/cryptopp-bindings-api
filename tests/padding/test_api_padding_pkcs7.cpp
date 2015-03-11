/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/padding/api_padding_pkcs7.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>
#include <string>

TEST(PaddingPkcs7Test, inheritance) {
    CryptoppApi::PaddingPkcs7 padding;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::PaddingInterface*>(&padding));
}

TEST(PaddingPkcs7Test, pad) {
    CryptoppApi::PaddingPkcs7 padding;

    // build expected data
    byte *expected1         = NULL;
    byte *expected2         = NULL;
    byte *expected3         = NULL;
    byte *expected4         = NULL;
    size_t expected1Length  = 0;
    size_t expected2Length  = 0;
    size_t expected3Length  = 0;
    size_t expected4Length  = 0;
    CryptoppApi::HexUtils::hex2bin("060606060606", 12, &expected1, expected1Length);
    CryptoppApi::HexUtils::hex2bin("617a65727479060606060606", 24, &expected2, expected2Length);
    CryptoppApi::HexUtils::hex2bin("7177657274790202", 16, &expected3, expected3Length);
    CryptoppApi::HexUtils::hex2bin("77786376626e0202", 16, &expected4, expected4Length);

    // build actual data
    std::string input2Str("azerty");
    std::string input3Str("qwerty");
    std::string input4Str("wxcvbn");
    const byte *input2 = reinterpret_cast<const byte*>(input2Str.c_str());
    const byte *input3 = reinterpret_cast<const byte*>(input3Str.c_str());
    const byte *input4 = reinterpret_cast<const byte*>(input4Str.c_str());

    byte *output1;
    byte *output2;
    byte *output3;
    byte *output4;
    size_t output1Length = 0;
    size_t output2Length = 0;
    size_t output3Length = 0;
    size_t output4Length = 0;
    padding.pad(6, NULL, 0, &output1, output1Length);
    padding.pad(6, input2, input2Str.length(), &output2, output2Length);
    padding.pad(8, input3, input3Str.length(), &output3, output3Length);
    padding.pad(4, input4, input4Str.length(), &output4, output4Length);

    // test data
    EXPECT_BYTE_ARRAY_EQ(expected1, expected1Length, output1, output1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, expected2Length, output2, output2Length);
    EXPECT_BYTE_ARRAY_EQ(expected3, expected3Length, output3, output3Length);
    EXPECT_BYTE_ARRAY_EQ(expected4, expected4Length, output4, output4Length);

    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
    delete[] expected4;
    delete[] output1;
    delete[] output2;
    delete[] output3;
    delete[] output4;
}

TEST(PaddingPkcs7Test, unpad) {
    CryptoppApi::PaddingPkcs7 padding;

    // build expected data
    std::string expected2Str("azerty");
    std::string expected3Str("qwerty");
    std::string expected4Str("wxcvbn");
    const byte *expected1   = NULL;
    const byte *expected2   = reinterpret_cast<const byte*>(expected2Str.c_str());
    const byte *expected3   = reinterpret_cast<const byte*>(expected3Str.c_str());
    const byte *expected4   = reinterpret_cast<const byte*>(expected4Str.c_str());
    size_t expected1Length  = 0;
    size_t expected2Length  = expected2Str.length();
    size_t expected3Length  = expected3Str.length();
    size_t expected4Length  = expected4Str.length();

    // build actual data
    byte *input1        = NULL;
    byte *input2        = NULL;
    byte *input3        = NULL;
    byte *input4        = NULL;
    size_t input1Length = 0;
    size_t input2Length = 0;
    size_t input3Length = 0;
    size_t input4Length = 0;
    CryptoppApi::HexUtils::hex2bin("060606060606", 12, &input1, input1Length);
    CryptoppApi::HexUtils::hex2bin("617a65727479060606060606", 24, &input2, input2Length);
    CryptoppApi::HexUtils::hex2bin("7177657274790202", 16, &input3, input3Length);
    CryptoppApi::HexUtils::hex2bin("77786376626e0202", 16, &input4, input4Length);

    byte *output1;
    byte *output2;
    byte *output3;
    byte *output4;
    size_t output1Length = 0;
    size_t output2Length = 0;
    size_t output3Length = 0;
    size_t output4Length = 0;
    padding.unpad(6, input1, input1Length, &output1, output1Length);
    padding.unpad(6, input2, input2Length, &output2, output2Length);
    padding.unpad(8, input3, input3Length, &output3, output3Length);
    padding.unpad(4, input4, input4Length, &output4, output4Length);

    // test data
    EXPECT_BYTE_ARRAY_EQ(expected1, expected1Length, output1, output1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, expected2Length, output2, output2Length);
    EXPECT_BYTE_ARRAY_EQ(expected3, expected3Length, output3, output3Length);
    EXPECT_BYTE_ARRAY_EQ(expected4, expected4Length, output4, output4Length);

    delete[] input1;
    delete[] input2;
    delete[] input3;
    delete[] input4;
    delete[] output1;
    delete[] output2;
    delete[] output3;
    delete[] output4;
}

TEST(PaddingPkcs7Test, can) {
    CryptoppApi::PaddingPkcs7 padding;
    EXPECT_TRUE(padding.canPad());
    EXPECT_TRUE(padding.canUnpad());
}

TEST(PaddingPkcs7Test, largeData) {
    CryptoppApi::PaddingPkcs7 padding;
    size_t input1Length     = 10485760;
    size_t input2Length     = input1Length + 16;
    byte *input1            = new byte[input1Length];
    byte *input2            = new byte[input2Length];
    byte *output1;
    byte *output2;
    size_t output1Length    = 0;
    size_t output2Length    = 0;

    memset(input2 + input1Length, 16, 16);
    padding.pad(16, input1, input1Length, &output1, output1Length);
    padding.unpad(16, input2, input2Length, &output2, output2Length);

    EXPECT_EQ(input2Length, output1Length);
    EXPECT_EQ(input1Length, output2Length);

    delete[] input1;
    delete[] input2;
    delete[] output1;
    delete[] output2;
}

TEST(PaddingPkcs7Test, padErrors) {
    CryptoppApi::PaddingPkcs7 padding;
    byte *output;
    size_t outputLength = 0;

    EXPECT_THROW_MSG(padding.pad(0, NULL, 0, &output, outputLength), CryptoppApi::Exception, "block size cannot be lower than 1, 0 given");
    EXPECT_THROW_MSG(padding.pad(257, NULL, 0, &output, outputLength), CryptoppApi::Exception, "PKCS #7 padding does not handle block sizes higher than 256");
}

TEST(PaddingPkcs7Test, unpadErrors) {
    CryptoppApi::PaddingPkcs7 padding;
    byte *output;
    size_t outputLength = 0;

    EXPECT_THROW_MSG(padding.unpad(0, NULL, 0, &output, outputLength), CryptoppApi::Exception, "block size cannot be lower than 1, 0 given");
    EXPECT_THROW_MSG(padding.unpad(257, NULL, 0, &output, outputLength), CryptoppApi::Exception, "PKCS #7 padding does not handle block sizes higher than 256");

    std::string input1  = "123";
    std::string input2  = "1234";
    byte *input3        = NULL;
    size_t input1Length = 0;
    CryptoppApi::HexUtils::hex2bin("04040304", 4, &input3, input1Length);

    EXPECT_THROW_MSG(padding.unpad(4, reinterpret_cast<const byte*>(input1.c_str()), input1.length(), &output, outputLength), CryptoppApi::Exception, "data length is not a multiple of block size (block size is 4, data size is 3)");
    EXPECT_THROW_MSG(padding.unpad(4, reinterpret_cast<const byte*>(input2.c_str()), input2.length(), &output, outputLength), CryptoppApi::Exception, "invalid PKCS #7 block padding found");
    EXPECT_THROW_MSG(padding.unpad(4, input3, 4, &output, outputLength), CryptoppApi::Exception, "invalid PKCS #7 block padding found");
}
