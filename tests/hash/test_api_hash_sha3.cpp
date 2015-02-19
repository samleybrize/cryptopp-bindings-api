/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/hash/api_hash_sha3.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

#if CRYPTOPP_SHA3_ENABLED == 1

// TODO 256
// TODO 384
// TODO 512

TEST(HashSha3_224Test, inheritance) {
    CryptoppApi::HashSha3_224 hash;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashTransformationInterface*>(&hash));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashInterface*>(&hash));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashAbstract*>(&hash));
}

TEST(HashSha3_224Test, infos) {
    CryptoppApi::HashSha3_224 hash;

    EXPECT_STREQ("sha3_224", hash.getName());
    EXPECT_EQ(72, hash.getBlockSize());
    EXPECT_EQ(28, hash.getDigestSize());
}

TEST(HashSha3_224Test, calculateDigest) {
    CryptoppApi::HashSha3_224 hash;

    // build expected digests
    byte *expected1;
    byte *expected2;
    size_t expected1Length = 0;
    size_t expected2Length = 0;
    CryptoppApi::HexUtils::hex2bin("2fa05a669e02a13295588c05a1e91b56d889cf5004f9971789a464bf", 56, &expected1, expected1Length);
    CryptoppApi::HexUtils::hex2bin("39ba050e26e31d0b3e1293a33dfbdecba37e2f0a6e851dd4bed8ccfc", 56, &expected2, expected2Length);

    // calculate actual digests
    char *input1        = "qwertyuiop";
    char *input2        = "azerty";
    size_t digestSize   = hash.getDigestSize();
    byte actual1[digestSize];
    byte actual2[digestSize];

    hash.calculateDigest(reinterpret_cast<byte*>(input1), strlen(input1), actual1);
    hash.calculateDigest(reinterpret_cast<byte*>(input2), strlen(input2), actual2);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected1, expected1Length, actual1, digestSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, expected2Length, actual2, digestSize);

    delete[] expected1;
    delete[] expected2;
}

TEST(HashSha3_224Test, update) {
    CryptoppApi::HashSha3_224 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("2fa05a669e02a13295588c05a1e91b56d889cf5004f9971789a464bf", 56, &expected, expectedLength);

    // calculate actual digest
    char *input1        = "qwerty";
    char *input2        = "uio";
    char *input3        = "p";
    size_t digestSize   = hash.getDigestSize();
    byte actual[digestSize];

    hash.update(reinterpret_cast<byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<byte*>(input2), strlen(input2));
    hash.update(reinterpret_cast<byte*>(input3), strlen(input3));

    hash.finalize(actual);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(HashSha3_224Test, restartNotNecessaryAfterFinalize) {
    CryptoppApi::HashSha3_224 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("2fa05a669e02a13295588c05a1e91b56d889cf5004f9971789a464bf", 56, &expected, expectedLength);

    // calculate actual digest
    char *input1        = "qwerty";
    char *input2        = "uio";
    char *input3        = "p";
    size_t digestSize   = hash.getDigestSize();
    byte actual[digestSize];

    hash.update(reinterpret_cast<byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<byte*>(input1), strlen(input1));
    hash.finalize(actual);

    hash.update(reinterpret_cast<byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<byte*>(input2), strlen(input2));
    hash.update(reinterpret_cast<byte*>(input3), strlen(input3));

    hash.finalize(actual);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(HashSha3_224Test, restart) {
    CryptoppApi::HashSha3_224 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("2fa05a669e02a13295588c05a1e91b56d889cf5004f9971789a464bf", 56, &expected, expectedLength);

    // calculate actual digest
    char *input1        = "qwerty";
    char *input2        = "uio";
    char *input3        = "p";
    size_t digestSize   = hash.getDigestSize();
    byte actual[digestSize];

    hash.update(reinterpret_cast<byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<byte*>(input1), strlen(input1));
    hash.restart();

    hash.update(reinterpret_cast<byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<byte*>(input2), strlen(input2));
    hash.update(reinterpret_cast<byte*>(input3), strlen(input3));

    hash.finalize(actual);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(HashSha3_224Test, largeData) {
    CryptoppApi::HashSha3_224 hash;

    size_t digestSize   = hash.getDigestSize();
    byte *input         = new byte[10485760];
    byte output[digestSize];

    hash.calculateDigest(input, 10485760, output);
    hash.update(input, 10485760);
    hash.finalize(output);

    delete[] input;
}

#endif /* CRYPTOPP_SHA3_ENABLED == 1 */
