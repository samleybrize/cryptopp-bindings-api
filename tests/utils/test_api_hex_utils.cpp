/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(HexUtilsTest, bin2hex) {
    char *actual1;
    char *actual2;
    size_t actual1Length    = 0;
    size_t actual2Length    = 0;
    byte input1[]           = {97, 122, 101, 114, 116, 121, 117, 105, 111, 112};
    byte input2[]           = {108, 83, 208, 107, 19, 201};
    CryptoppApi::HexUtils::bin2hex(input1, sizeof(input1), &actual1, actual1Length);
    CryptoppApi::HexUtils::bin2hex(input2, sizeof(input2), &actual2, actual2Length);

    std::string actual1Str(actual1, actual1Length);
    std::string actual2Str(actual2, actual2Length);

    std::string expected1("617a6572747975696f70");
    std::string expected2("6c53d06b13c9");
    EXPECT_STREQ(expected1.c_str(), actual1Str.c_str());
    EXPECT_STREQ(expected2.c_str(), actual2Str.c_str());

    delete[] actual1;
    delete[] actual2;
}

TEST(HexUtilsTest, hex2bin) {
    byte *actual1;
    byte *actual2;
    size_t actual1Length = 0;
    size_t actual2Length = 0;
    CryptoppApi::HexUtils::hex2bin("617a6572747975696f70", 20, &actual1, actual1Length);
    CryptoppApi::HexUtils::hex2bin("6c53d06b13c9", 12, &actual2, actual2Length);

    byte expected1[] = {97, 122, 101, 114, 116, 121, 117, 105, 111, 112};
    byte expected2[] = {108, 83, 208, 107, 19, 201};
    EXPECT_BYTE_ARRAY_EQ(expected1, sizeof(expected1), actual1, actual1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, sizeof(expected2), actual2, actual2Length);

    delete[] actual1;
    delete[] actual2;
}
