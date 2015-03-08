/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/hash/api_hash_md5.h"
#include "src/hash/api_hash_sha1.h"
#include "src/keying/api_symmetric_key_abstract.h"
#include "src/mac/api_mac_hmac.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(MacHmacTest, inheritance) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashTransformationInterface*>(&mac));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::MacInterface*>(&mac));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::MacAbstract*>(&mac));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&mac));
}

TEST(MacHmacTest, infosSha1) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    EXPECT_STREQ("hmac(sha1)", mac.getName());
    EXPECT_EQ(0, mac.getBlockSize());
    EXPECT_EQ(20, mac.getDigestSize());
}

TEST(MacHmacTest, infosMd5) {
    CryptoppApi::HashMd5 hash;
    CryptoppApi::MacHmac mac(&hash);

    EXPECT_STREQ("hmac(md5)", mac.getName());
    EXPECT_EQ(0, mac.getBlockSize());
    EXPECT_EQ(16, mac.getDigestSize());
}

TEST(MacHmacTest, isValidKeyLength) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    EXPECT_TRUE(mac.isValidKeyLength(3));
    EXPECT_TRUE(mac.isValidKeyLength(16));
    EXPECT_TRUE(mac.isValidKeyLength(23));
    EXPECT_TRUE(mac.isValidKeyLength(125));
    EXPECT_TRUE(mac.isValidKeyLength(0));
}

TEST(MacHmacTest, setGetKey) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10111213141516171819", 50, &key, keyLength);

    mac.setKey(key, keyLength);

    // get key
    size_t key2Length   = mac.getKeyLength();
    byte *key2          = new byte[key2Length];
    mac.getKey(key2);

    // test key
    EXPECT_BYTE_ARRAY_EQ(key, keyLength, key2, key2Length);

    delete[] key;
    delete[] key2;
}

TEST(MacHmacTest, calculateDigestSha1) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10111213141516171819", 50, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digests
    byte *expected1;
    byte *expected2;
    size_t expected1Length = 0;
    size_t expected2Length = 0;
    CryptoppApi::HexUtils::hex2bin("b7b39196ab5f9c0cf7863b8e0a0bda37aea2c93e", 40, &expected1, expected1Length);
    CryptoppApi::HexUtils::hex2bin("286d11632a144649124bf912f2826ee80887206f", 40, &expected2, expected2Length);

    // calculate actual digests
    const char *input1  = "qwertyuiop";
    const char *input2  = "azerty";
    size_t digestSize   = mac.getDigestSize();
    byte actual1[digestSize];
    byte actual2[digestSize];

    mac.calculateDigest(reinterpret_cast<const byte*>(input1), strlen(input1), actual1);
    mac.calculateDigest(reinterpret_cast<const byte*>(input2), strlen(input2), actual2);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected1, expected1Length, actual1, digestSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, expected2Length, actual2, digestSize);

    delete[] expected1;
    delete[] expected2;
}

TEST(MacHmacTest, calculateDigestMd5) {
    CryptoppApi::HashMd5 hash;
    CryptoppApi::MacHmac mac(&hash);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 32, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digests
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("9294727a3638bb1c13f48ef8158bfc9d", 32, &expected, expectedLength);

    // calculate actual digests
    const char *input   = "Hi There";
    size_t digestSize   = mac.getDigestSize();
    byte actual[digestSize];

    mac.calculateDigest(reinterpret_cast<const byte*>(input), strlen(input), actual);

    // test digest
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(MacHmacTest, update) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10111213141516171819", 50, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("b7b39196ab5f9c0cf7863b8e0a0bda37aea2c93e", 40, &expected, expectedLength);

    // calculate actual digest
    const char *input1  = "qwerty";
    const char *input2  = "uio";
    const char *input3  = "p";
    size_t digestSize   = mac.getDigestSize();
    byte actual[digestSize];

    mac.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    mac.update(reinterpret_cast<const byte*>(input2), strlen(input2));
    mac.update(reinterpret_cast<const byte*>(input3), strlen(input3));

    mac.finalize(actual);

    // test digest
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(MacHmacTest, restartNotNecessaryAfterFinalize) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10111213141516171819", 50, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("b7b39196ab5f9c0cf7863b8e0a0bda37aea2c93e", 40, &expected, expectedLength);

    // calculate actual digest
    const char *input1  = "qwerty";
    const char *input2  = "uio";
    const char *input3  = "p";
    size_t digestSize   = mac.getDigestSize();
    byte actual[digestSize];

    mac.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    mac.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    mac.finalize(actual);

    mac.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    mac.update(reinterpret_cast<const byte*>(input2), strlen(input2));
    mac.update(reinterpret_cast<const byte*>(input3), strlen(input3));

    mac.finalize(actual);

    // test digest
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(MacHmacTest, restart) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10111213141516171819", 50, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("b7b39196ab5f9c0cf7863b8e0a0bda37aea2c93e", 40, &expected, expectedLength);

    // calculate actual digest
    const char *input1  = "qwerty";
    const char *input2  = "uio";
    const char *input3  = "p";
    size_t digestSize   = mac.getDigestSize();
    byte actual[digestSize];

    mac.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    mac.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    mac.restart();

    mac.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    mac.update(reinterpret_cast<const byte*>(input2), strlen(input2));
    mac.update(reinterpret_cast<const byte*>(input3), strlen(input3));

    mac.finalize(actual);

    // test digest
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(MacHmacTest, largeData) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10111213141516171819", 50, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // calculate digest
    size_t digestSize   = mac.getDigestSize();
    byte *input         = new byte[10485760];
    byte output[digestSize];

    mac.calculateDigest(input, 10485760, output);
    mac.update(input, 10485760);
    mac.finalize(output);

    delete[] input;
}

TEST(MacHmacTest, setEmptyKey) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    mac.setKey(NULL, 0);
}

TEST(MacHmacTest, calculateDigestWithoutKey) {
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("74cc2e382f34db671647ea987cc2e041e8740a22", 40, &expected, expectedLength);

    // calculate digest without key
    size_t digestSize   = mac.getDigestSize();
    const char *input   = "qwerty";
    byte actual[digestSize];
    mac.calculateDigest(reinterpret_cast<const byte*>(input), strlen(input), actual);
    mac.update(reinterpret_cast<const byte*>(input), strlen(input));
    mac.finalize(actual);

    // test digest
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}
