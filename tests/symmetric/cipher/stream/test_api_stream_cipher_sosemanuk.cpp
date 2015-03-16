/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/symmetric/cipher/stream/api_stream_cipher_sosemanuk.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(StreamCipherSosemanukTest, inheritance) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricCipherInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricTransformationInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::StreamCipherInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::StreamCipherAbstract*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricIvAbstract*>(&cipher));
}

TEST(StreamCipherSosemanukTest, infos) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    EXPECT_STREQ("sosemanuk", cipher.getName());
    EXPECT_EQ(1, cipher.getBlockSize());
}

TEST(StreamCipherSosemanukTest, isValidKeyLength) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    EXPECT_TRUE(cipher.isValidKeyLength(16));
    EXPECT_TRUE(cipher.isValidKeyLength(23));
    EXPECT_TRUE(cipher.isValidKeyLength(9));
    EXPECT_FALSE(cipher.isValidKeyLength(0));
    EXPECT_FALSE(cipher.isValidKeyLength(33));
}

TEST(StreamCipherSosemanukTest, isValidIvLength) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    EXPECT_TRUE(cipher.isValidIvLength(16));
    EXPECT_FALSE(cipher.isValidIvLength(15));
    EXPECT_FALSE(cipher.isValidIvLength(17));
}

TEST(StreamCipherSosemanukTest, setGetKey) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    // build keys
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10", 32, &key, keyLength);

    // set/get keys
    size_t key0Length = cipher.getKeyLength();

    cipher.setKey(key, keyLength);
    size_t keyGetLength = cipher.getKeyLength();
    byte keyGet[keyGetLength];
    cipher.getKey(keyGet);

    // test keys
    EXPECT_EQ(0, key0Length);
    EXPECT_BYTE_ARRAY_EQ(key, keyLength, keyGet, keyGetLength);

    delete[] key;
}

TEST(StreamCipherSosemanukTest, setGetIv) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10", 32, &iv, ivLength);

    // set/get iv
    size_t iv0Length = cipher.getIvLength();

    cipher.setIv(iv, ivLength);
    size_t ivGetLength = cipher.getIvLength();
    byte ivGet[ivGetLength];
    cipher.getIv(ivGet);

    // test ivs
    EXPECT_EQ(0, iv0Length);
    EXPECT_BYTE_ARRAY_EQ(iv, ivLength, ivGet, ivGetLength);

    delete[] iv;
}

TEST(StreamCipherSosemanukTest, encrypt) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("a7c083feb7", 10, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff", 32, &iv, ivLength);

    // build block
    byte *block;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("be6a431a935cb90e2221ebb7ef502328", 32, &expected2, dummyLength);
    cipher.setKey(key, keyLength);
    cipher.setIv(iv, ivLength);
    cipher.encrypt(block, output1, dataSize);
    cipher.encrypt(block, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;
    delete[] key;
    delete[] iv;
    delete[] block;
}

TEST(StreamCipherSosemanukTest, decrypt) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *block1;
    byte *block2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("a7c083feb7", 10, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff", 32, &iv, ivLength);

    // build expected data
    byte *expected;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("be6a431a935cb90e2221ebb7ef502328", 32, &block2, dummyLength);
    cipher.setKey(key, keyLength);
    cipher.setIv(iv, ivLength);
    cipher.decrypt(block1, output1, dataSize);
    cipher.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;
    delete[] key;
    delete[] iv;
    delete[] expected;
}

TEST(StreamCipherSosemanukTest, restartEncryption) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("a7c083feb7", 10, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff", 32, &iv, ivLength);
    cipher.setIv(iv, ivLength);

    // build blocks
    byte *block;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &expected, dummyLength);
    cipher.setKey(key, keyLength);
    cipher.encrypt(block, output1, dataSize);
    cipher.restart();
    cipher.encrypt(block, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected, dataSize, output2, dataSize);


    delete[] key;
    delete[] iv;
    delete[] block;
    delete[] expected;
}

TEST(StreamCipherSosemanukTest, restartDecryption) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("a7c083feb7", 10, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff", 32, &iv, ivLength);
    cipher.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("be6a431a935cb90e2221ebb7ef502328", 32, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("40eb910cbfc6a90326a8b7f2a5277273", 32, &expected2, dummyLength);
    cipher.setKey(key, keyLength);
    cipher.decrypt(block1, output1, dataSize);
    cipher.restart();
    cipher.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] key;
    delete[] iv;
    delete[] block1;
    delete[] block2;
    delete[] expected1;
    delete[] expected2;
}

TEST(StreamCipherSosemanukTest, largeData) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    std::string key("1234567890123456");
    std::string iv("1234567890123456");
    cipher.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    cipher.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    size_t dataSize = 10485760;
    byte *input     = new byte[dataSize];
    byte *output    = new byte[dataSize];
    memset(input, 125, dataSize);
    cipher.encrypt(input, output, dataSize);
    cipher.decrypt(input, output, dataSize);

    delete[] input;
    delete[] output;
}

TEST(StreamCipherSosemanukTest, isStream) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    std::string key("1234567890123456");
    std::string iv("1234567890123456");
    cipher.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    cipher.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    std::string dataStr("12345678901234567");
    const byte *data    = reinterpret_cast<const byte*>(dataStr.c_str());
    size_t dataLength   = dataStr.length();
    byte output[dataLength];

    cipher.encrypt(data, output, dataLength);
    cipher.decrypt(data, output, dataLength);
}

TEST(StreamCipherSosemanukTest, invalidKey) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    byte key1[33];
    byte key2[0];
    memset(key1, 0, 33);

    EXPECT_THROW_MSG(cipher.setKey(key1, 33), CryptoppApi::Exception, "33 is not a valid key length");
    EXPECT_THROW_MSG(cipher.setKey(key2, 0), CryptoppApi::Exception, "a key is required");
}

TEST(StreamCipherSosemanukTest, invalidIv) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    byte iv1[] = {45, 12, 14};
    byte iv2[0];

    EXPECT_THROW_MSG(cipher.setIv(iv1, 3), CryptoppApi::Exception, "3 is not a valid initialization vector length");
    EXPECT_THROW_MSG(cipher.setIv(iv2, 0), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(StreamCipherSosemanukTest, cryptWithoutKey) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    size_t inputLength = cipher.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(cipher.encrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(cipher.decrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
}

TEST(StreamCipherSosemanukTest, cryptWithoutIv) {
    CryptoppApi::StreamCipherSosemanuk cipher;

    std::string key("1234567890123456");
    cipher.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    size_t inputLength = cipher.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(cipher.encrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
    EXPECT_THROW_MSG(cipher.decrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
}
