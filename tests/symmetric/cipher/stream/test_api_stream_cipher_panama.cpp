/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/symmetric/cipher/stream/api_stream_cipher_panama.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(StreamCipherPanamaTest, inheritance) {
    CryptoppApi::StreamCipherPanama cipher;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricCipherInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricTransformationInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::StreamCipherInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::StreamCipherAbstract*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricIvAbstract*>(&cipher));
}

TEST(StreamCipherPanamaTest, infos) {
    CryptoppApi::StreamCipherPanama cipher;

    EXPECT_STREQ("panama", cipher.getName());
    EXPECT_EQ(1, cipher.getBlockSize());
}

TEST(StreamCipherPanamaTest, isValidKeyLength) {
    CryptoppApi::StreamCipherPanama cipher;

    EXPECT_TRUE(cipher.isValidKeyLength(32));
    EXPECT_FALSE(cipher.isValidKeyLength(23));
    EXPECT_FALSE(cipher.isValidKeyLength(9));
    EXPECT_FALSE(cipher.isValidKeyLength(0));
    EXPECT_FALSE(cipher.isValidKeyLength(33));
}

TEST(StreamCipherPanamaTest, isValidIvLength) {
    CryptoppApi::StreamCipherPanama cipher;

    EXPECT_TRUE(cipher.isValidIvLength(32));
    EXPECT_FALSE(cipher.isValidIvLength(15));
    EXPECT_FALSE(cipher.isValidIvLength(33));
}

TEST(StreamCipherPanamaTest, setGetKey) {
    CryptoppApi::StreamCipherPanama cipher;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f", 64, &key, keyLength);

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

TEST(StreamCipherPanamaTest, setGetIv) {
    CryptoppApi::StreamCipherPanama cipher;

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10", 64, &iv, ivLength);

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

TEST(StreamCipherPanamaTest, encrypt) {
    CryptoppApi::StreamCipherPanama cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("f07f5ff2ccd01a0a7d44acd6d239c2af0da1ff35275baf5dfa6e09411b79d8b9", 64, &iv, ivLength);

    // build block
    byte *block;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("33d6c41cea88376420433bd3b7f88b27", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("506ace67d9841193058773d9b13b33b7", 32, &expected2, dummyLength);
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

TEST(StreamCipherPanamaTest, decrypt) {
    CryptoppApi::StreamCipherPanama cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *block1;
    byte *block2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("f07f5ff2ccd01a0a7d44acd6d239c2af0da1ff35275baf5dfa6e09411b79d8b9", 64, &iv, ivLength);

    // build expected data
    byte *expected;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("33d6c41cea88376420433bd3b7f88b27", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("506ace67d9841193058773d9b13b33b7", 32, &block2, dummyLength);
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

TEST(StreamCipherPanamaTest, encryptBigEndian) {
    CryptoppApi::StreamCipherPanama cipher(CryptoppApi::Endianness::E_BIG_ENDIAN);
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("f07f5ff2ccd01a0a7d44acd6d239c2af0da1ff35275baf5dfa6e09411b79d8b9", 64, &iv, ivLength);

    // build block
    byte *block;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("9df3d24ff46ccd8db521339fd4f788f8", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("bb2767e89d14ca669c8f7b311a8bef6b", 32, &expected2, dummyLength);
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

TEST(StreamCipherPanamaTest, decryptBigEndian) {
    CryptoppApi::StreamCipherPanama cipher(CryptoppApi::Endianness::E_BIG_ENDIAN);
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *block1;
    byte *block2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("f07f5ff2ccd01a0a7d44acd6d239c2af0da1ff35275baf5dfa6e09411b79d8b9", 64, &iv, ivLength);

    // build expected data
    byte *expected;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("9df3d24ff46ccd8db521339fd4f788f8", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("bb2767e89d14ca669c8f7b311a8bef6b", 32, &block2, dummyLength);
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

TEST(StreamCipherPanamaTest, restartEncryption) {
    CryptoppApi::StreamCipherPanama cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("f07f5ff2ccd01a0a7d44acd6d239c2af0da1ff35275baf5dfa6e09411b79d8b9", 64, &iv, ivLength);
    cipher.setIv(iv, ivLength);

    // build blocks
    byte *block;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("33d6c41cea88376420433bd3b7f88b27", 32, &expected, dummyLength);
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

TEST(StreamCipherPanamaTest, restartDecryption) {
    CryptoppApi::StreamCipherPanama cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("f07f5ff2ccd01a0a7d44acd6d239c2af0da1ff35275baf5dfa6e09411b79d8b9", 64, &iv, ivLength);
    cipher.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("33d6c41cea88376420433bd3b7f88b27", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("506ace67d9841193058773d9b13b33b7", 32, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("63bc0a7b330c26f725c4480a06c3b890", 32, &expected2, dummyLength);
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

TEST(StreamCipherPanamaTest, largeData) {
    CryptoppApi::StreamCipherPanama cipher;

    std::string key("12345678901234567890123456789012");
    std::string iv("12345678901234567890123456789012");
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

TEST(StreamCipherPanamaTest, isStream) {
    CryptoppApi::StreamCipherPanama cipher;

    std::string key("12345678901234567890123456789012");
    std::string iv("12345678901234567890123456789012");
    cipher.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    cipher.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    std::string dataStr("12345678901234567");
    const byte *data    = reinterpret_cast<const byte*>(dataStr.c_str());
    size_t dataLength   = dataStr.length();
    byte output[dataLength];

    cipher.encrypt(data, output, dataLength);
    cipher.decrypt(data, output, dataLength);
}

TEST(StreamCipherPanamaTest, invalidKey) {
    CryptoppApi::StreamCipherPanama cipher;

    byte key1[33];
    byte key2[0];
    memset(key1, 0, 33);

    EXPECT_THROW_MSG(cipher.setKey(key1, 33), CryptoppApi::Exception, "33 is not a valid key length");
    EXPECT_THROW_MSG(cipher.setKey(key2, 0), CryptoppApi::Exception, "a key is required");
}

TEST(StreamCipherPanamaTest, invalidIv) {
    CryptoppApi::StreamCipherPanama cipher;

    byte iv1[] = {45, 12, 14};
    byte iv2[0];

    EXPECT_THROW_MSG(cipher.setIv(iv1, 3), CryptoppApi::Exception, "3 is not a valid initialization vector length");
    EXPECT_THROW_MSG(cipher.setIv(iv2, 0), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(StreamCipherPanamaTest, cryptWithoutKey) {
    CryptoppApi::StreamCipherPanama cipher;

    size_t inputLength = cipher.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(cipher.encrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(cipher.decrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
}

TEST(StreamCipherPanamaTest, cryptWithoutIv) {
    CryptoppApi::StreamCipherPanama cipher;

    std::string key("12345678901234567890123456789012");
    cipher.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    size_t inputLength = cipher.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(cipher.encrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
    EXPECT_THROW_MSG(cipher.decrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
}
