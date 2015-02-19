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

TEST(HashSha3_384Test, inheritance) {
    CryptoppApi::HashSha3_384 hash;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashTransformationInterface*>(&hash));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashInterface*>(&hash));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashAbstract*>(&hash));
}

TEST(HashSha3_384Test, infos) {
    CryptoppApi::HashSha3_384 hash;

    EXPECT_STREQ("sha3_384", hash.getName());
    EXPECT_EQ(136, hash.getBlockSize());
    EXPECT_EQ(48, hash.getDigestSize());
}

TEST(HashSha3_384Test, calculateDigest) {
    CryptoppApi::HashSha3_384 hash;

    // build expected digests
    byte *expected1;
    byte *expected2;
    size_t expected1Length = 0;
    size_t expected2Length = 0;
    CryptoppApi::HexUtils::hex2bin("979f984c6de6d69d4137c8a92d4c2509a7adcc4d40e9880f761dcc45498408fa475ab56f656fc9f41b05d5f0c42bb92a", 96, &expected1, expected1Length);
    CryptoppApi::HexUtils::hex2bin("e27d047d91207046d60f405ced5d0f177d81374b6cfa7851a81966f36434e4b1c65b8e1eb6dc7965b782abdfba986bea", 96, &expected2, expected2Length);

    // calculate actual digests
    const char *input1  = "qwertyuiop";
    const char *input2  = "azerty";
    size_t digestSize   = hash.getDigestSize();
    byte actual1[digestSize];
    byte actual2[digestSize];

    hash.calculateDigest(reinterpret_cast<const byte*>(input1), strlen(input1), actual1);
    hash.calculateDigest(reinterpret_cast<const byte*>(input2), strlen(input2), actual2);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected1, expected1Length, actual1, digestSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, expected2Length, actual2, digestSize);

    delete[] expected1;
    delete[] expected2;
}

TEST(HashSha3_384Test, update) {
    CryptoppApi::HashSha3_384 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("979f984c6de6d69d4137c8a92d4c2509a7adcc4d40e9880f761dcc45498408fa475ab56f656fc9f41b05d5f0c42bb92a", 96, &expected, expectedLength);

    // calculate actual digest
    const char *input1  = "qwerty";
    const char *input2  = "uio";
    const char *input3  = "p";
    size_t digestSize   = hash.getDigestSize();
    byte actual[digestSize];

    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<const byte*>(input2), strlen(input2));
    hash.update(reinterpret_cast<const byte*>(input3), strlen(input3));

    hash.finalize(actual);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(HashSha3_384Test, restartNotNecessaryAfterFinalize) {
    CryptoppApi::HashSha3_384 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("979f984c6de6d69d4137c8a92d4c2509a7adcc4d40e9880f761dcc45498408fa475ab56f656fc9f41b05d5f0c42bb92a", 96, &expected, expectedLength);

    // calculate actual digest
    const char *input1  = "qwerty";
    const char *input2  = "uio";
    const char *input3  = "p";
    size_t digestSize   = hash.getDigestSize();
    byte actual[digestSize];

    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.finalize(actual);

    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<const byte*>(input2), strlen(input2));
    hash.update(reinterpret_cast<const byte*>(input3), strlen(input3));

    hash.finalize(actual);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(HashSha3_384Test, restart) {
    CryptoppApi::HashSha3_384 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("979f984c6de6d69d4137c8a92d4c2509a7adcc4d40e9880f761dcc45498408fa475ab56f656fc9f41b05d5f0c42bb92a", 96, &expected, expectedLength);

    // calculate actual digest
    const char *input1  = "qwerty";
    const char *input2  = "uio";
    const char *input3  = "p";
    size_t digestSize   = hash.getDigestSize();
    byte actual[digestSize];

    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.restart();

    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<const byte*>(input2), strlen(input2));
    hash.update(reinterpret_cast<const byte*>(input3), strlen(input3));

    hash.finalize(actual);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(HashSha3_384Test, largeData) {
    CryptoppApi::HashSha3_384 hash;

    size_t digestSize   = hash.getDigestSize();
    byte *input         = new byte[10485760];
    byte output[digestSize];

    hash.calculateDigest(input, 10485760, output);
    hash.update(input, 10485760);
    hash.finalize(output);

    delete[] input;
}

#endif /* CRYPTOPP_SHA3_ENABLED == 1 */
