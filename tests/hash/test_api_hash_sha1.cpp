/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/hash/api_hash_sha1.h"
#include "src/mac/api_mac_hmac.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(HashSha1Test, inheritance) {
    CryptoppApi::HashSha1 hash;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashTransformationInterface*>(&hash));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashInterface*>(&hash));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashAbstract*>(&hash));
}

TEST(HashSha1Test, infos) {
    CryptoppApi::HashSha1 hash;

    EXPECT_STREQ("sha1", hash.getName());
    EXPECT_EQ(64, hash.getBlockSize());
    EXPECT_EQ(20, hash.getDigestSize());
}

TEST(HashSha1Test, calculateDigest) {
    CryptoppApi::HashSha1 hash;

    // build expected digests
    byte *expected1;
    byte *expected2;
    size_t expected1Length = 0;
    size_t expected2Length = 0;
    CryptoppApi::HexUtils::hex2bin("b0399d2029f64d445bd131ffaa399a42d2f8e7dc", 40, &expected1, expected1Length);
    CryptoppApi::HexUtils::hex2bin("9cf95dacd226dcf43da376cdb6cbba7035218921", 40, &expected2, expected2Length);

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

TEST(HashSha1Test, update) {
    CryptoppApi::HashSha1 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("b0399d2029f64d445bd131ffaa399a42d2f8e7dc", 40, &expected, expectedLength);

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

TEST(HashSha1Test, restartNotNecessaryAfterFinalize) {
    CryptoppApi::HashSha1 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("b0399d2029f64d445bd131ffaa399a42d2f8e7dc", 40, &expected, expectedLength);

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

TEST(HashSha1Test, restart) {
    CryptoppApi::HashSha1 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("b0399d2029f64d445bd131ffaa399a42d2f8e7dc", 40, &expected, expectedLength);

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

TEST(HashSha1Test, largeData) {
    CryptoppApi::HashSha1 hash;

    size_t digestSize   = hash.getDigestSize();
    byte *input         = new byte[10485760];
    byte output[digestSize];

    hash.calculateDigest(input, 10485760, output);
    hash.update(input, 10485760);
    hash.finalize(output);

    delete[] input;
}

TEST(HashSha1Test, hmac) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("675b0b3a1b4ddf4e124872da6c2f632bfed957e9", 40, &expected, expectedLength);

    // calculate digest
    std::string inputStr("Hi There");
    const byte *input   = reinterpret_cast<const byte*>(inputStr.c_str());
    size_t inputLength  = inputStr.length();

    byte *key;
    size_t keyLength    = 0;
    CryptoppApi::HexUtils::hex2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 32, &key, keyLength);
    mac.setKey(key, keyLength);

    byte actual[mac.getDigestSize()];
    mac.calculateDigest(input, inputLength, actual);
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, mac.getDigestSize());

    delete[] expected;
    delete[] key;
}
