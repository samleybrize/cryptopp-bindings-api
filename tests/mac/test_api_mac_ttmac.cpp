/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/mac/api_mac_ttmac.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(MacTtmacTest, inheritance) {
    CryptoppApi::MacTtmac mac;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashTransformationInterface*>(&mac));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::MacInterface*>(&mac));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::MacAbstract*>(&mac));
}

TEST(MacTtmacTest, infos) {
    CryptoppApi::MacTtmac mac;

    EXPECT_STREQ("two-track-mac", mac.getName());
    EXPECT_EQ(64, mac.getBlockSize());
    EXPECT_EQ(20, mac.getDigestSize());
}

TEST(MacTtmacTest, isValidKeyLength) {
    CryptoppApi::MacTtmac mac;

    EXPECT_TRUE(mac.isValidKeyLength(20));
    EXPECT_FALSE(mac.isValidKeyLength(19));
    EXPECT_FALSE(mac.isValidKeyLength(21));
}

TEST(MacTtmacTest, setGetKey) {
    CryptoppApi::MacTtmac mac;

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff01234567", 40, &key, keyLength);

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

TEST(MacTtmacTest, calculateDigest) {
    CryptoppApi::MacTtmac mac;

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff01234567", 40, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digests
    byte *expected1;
    byte *expected2;
    size_t expected1Length = 0;
    size_t expected2Length = 0;
    CryptoppApi::HexUtils::hex2bin("e64c1b6d1e1b062b57bafabe75816a121c2f7b34", 40, &expected1, expected1Length);
    CryptoppApi::HexUtils::hex2bin("b27165d2f7de41c23aabe559cad7cc592fb50194", 40, &expected2, expected2Length);

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

TEST(MacTtmacTest, update) {
    CryptoppApi::MacTtmac mac;

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff01234567", 40, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("e64c1b6d1e1b062b57bafabe75816a121c2f7b34", 40, &expected, expectedLength);

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

TEST(MacTtmacTest, restartNotNecessaryAfterFinalize) {
    CryptoppApi::MacTtmac mac;

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff01234567", 40, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("e64c1b6d1e1b062b57bafabe75816a121c2f7b34", 40, &expected, expectedLength);

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

TEST(MacTtmacTest, restart) {
    CryptoppApi::MacTtmac mac;

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff01234567", 40, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("e64c1b6d1e1b062b57bafabe75816a121c2f7b34", 40, &expected, expectedLength);

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

TEST(MacTtmacTest, largeData) {
    CryptoppApi::MacTtmac mac;

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff01234567", 40, &key, keyLength);

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

TEST(MacTtmacTest, setInvalidKey) {
    CryptoppApi::MacTtmac mac;

    byte key[3];
    EXPECT_THROW_MSG(mac.setKey(key, 3), CryptoppApi::Exception, "3 is not a valid key length");
    EXPECT_THROW_MSG(mac.setKey(NULL, 0), CryptoppApi::Exception, "a key is required");
}

TEST(MacTtmacTest, calculateDigestWithoutKey) {
    CryptoppApi::MacTtmac mac;

    // calculate digest without key
    size_t digestSize   = mac.getDigestSize();
    const char *input   = "qwerty";
    byte actual[digestSize];

    EXPECT_THROW_MSG(mac.calculateDigest(reinterpret_cast<const byte*>(input), strlen(input), actual), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mac.update(reinterpret_cast<const byte*>(input), strlen(input)), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mac.finalize(actual), CryptoppApi::Exception, "a key is required");
}
