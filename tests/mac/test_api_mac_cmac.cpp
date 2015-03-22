/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/keying/api_symmetric_key_abstract.h"
#include "src/mac/api_mac_cmac.h"
#include "src/symmetric/cipher/block/api_block_cipher_aes.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(MacCmacTest, inheritance) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashTransformationInterface*>(&mac));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::MacInterface*>(&mac));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::MacAbstract*>(&mac));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&mac));
}

TEST(MacCmacTest, infos) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    EXPECT_STREQ("cmac(aes)", mac.getName());
    EXPECT_EQ(0, mac.getBlockSize());
    EXPECT_EQ(16, mac.getDigestSize());
}

TEST(MacCmacTest, isValidKeyLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    EXPECT_TRUE(mac.isValidKeyLength(32));
    EXPECT_TRUE(mac.isValidKeyLength(24));
    EXPECT_TRUE(mac.isValidKeyLength(16));
    EXPECT_FALSE(mac.isValidKeyLength(23));
    EXPECT_FALSE(mac.isValidKeyLength(125));
    EXPECT_FALSE(mac.isValidKeyLength(0));
}

TEST(MacCmacTest, setGetKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10", 32, &key, keyLength);

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

TEST(MacCmacTest, calculateDigest) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digests
    byte *expected1;
    byte *expected2;
    size_t expected1Length = 0;
    size_t expected2Length = 0;
    CryptoppApi::HexUtils::hex2bin("caa7624159a7b2f383509739843c8f3f", 32, &expected1, expected1Length);
    CryptoppApi::HexUtils::hex2bin("6cc65b89ebbfbbb933a0db79d8c5f629", 32, &expected2, expected2Length);

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

TEST(MacCmacTest, update) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("caa7624159a7b2f383509739843c8f3f", 32, &expected, expectedLength);

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

TEST(MacCmacTest, restartNotNecessaryAfterFinalize) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("caa7624159a7b2f383509739843c8f3f", 32, &expected, expectedLength);

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

TEST(MacCmacTest, restart) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("caa7624159a7b2f383509739843c8f3f", 32, &expected, expectedLength);

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

TEST(MacCmacTest, largeData) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    // set key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key, keyLength);

    mac.setKey(key, keyLength);
    delete[] key;

    // calculate digest
    size_t digestSize   = mac.getDigestSize();
    byte *input         = new byte[10485760];
    byte output[digestSize];
    memset(input, 0, 10485760);

    mac.calculateDigest(input, 10485760, output);
    mac.update(input, 10485760);
    mac.finalize(output);

    delete[] input;
}

TEST(MacCmacTest, setEmptyKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    EXPECT_THROW_MSG(mac.setKey(NULL, 0), CryptoppApi::Exception, "a key is required");
}

TEST(MacCmacTest, calculateDigestWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac(&cipher);

    // calculate digest without key
    size_t digestSize   = mac.getDigestSize();
    const char *input   = "qwerty";
    byte actual[digestSize];

    EXPECT_THROW_MSG(mac.calculateDigest(reinterpret_cast<const byte*>(input), strlen(input), actual), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mac.update(reinterpret_cast<const byte*>(input), strlen(input)), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mac.finalize(actual), CryptoppApi::Exception, "a key is required");
}

TEST(MacCmacTest, keyNotMatchingUnderlyingOne) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::MacCmac mac1(&cipher);
    CryptoppApi::MacCmac mac2(&cipher);

    std::string key1("1234567890123456");
    std::string key2("azertyuiopqwerty");
    std::string key3("wxcvbnqsdfghjklm");
    mac1.setKey(reinterpret_cast<const byte*>(key1.c_str()), key1.length());

    size_t inputLength = 20;
    byte input[inputLength];
    byte output[mac1.getDigestSize()];

    mac2.setKey(reinterpret_cast<const byte*>(key2.c_str()), key2.length());
    EXPECT_THROW_MSG(mac1.calculateDigest(input, inputLength, output), CryptoppApi::Exception, "key is not matching the one owned by the underlying cipher object");

    cipher.setKey(reinterpret_cast<const byte*>(key3.c_str()), key3.length());
    EXPECT_THROW_MSG(mac1.calculateDigest(input, inputLength, output), CryptoppApi::Exception, "key is not matching the one owned by the underlying cipher object");
}
