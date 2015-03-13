/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/symmetric/cipher/block/api_block_cipher_aes.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(BlockCipherAesTest, inheritance) {
    CryptoppApi::BlockCipherAes cipher;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricCipherInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::BlockCipherInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::BlockCipherAbstract*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&cipher));
}

TEST(BlockCipherAesTest, infosSha1) {
    CryptoppApi::BlockCipherAes cipher;

    EXPECT_STREQ("aes", cipher.getName());
    EXPECT_EQ(16, cipher.getBlockSize());
}

TEST(BlockCipherAesTest, isValidKeyLength) {
    CryptoppApi::BlockCipherAes cipher;

    EXPECT_TRUE(cipher.isValidKeyLength(16));
    EXPECT_FALSE(cipher.isValidKeyLength(15));
    EXPECT_FALSE(cipher.isValidKeyLength(17));

    EXPECT_TRUE(cipher.isValidKeyLength(24));
    EXPECT_FALSE(cipher.isValidKeyLength(23));
    EXPECT_FALSE(cipher.isValidKeyLength(25));

    EXPECT_TRUE(cipher.isValidKeyLength(32));
    EXPECT_FALSE(cipher.isValidKeyLength(31));
    EXPECT_FALSE(cipher.isValidKeyLength(33));
}

TEST(BlockCipherAesTest, setGetKey) {
    CryptoppApi::BlockCipherAes cipher;

    // build keys
    byte *key128;
    byte *key192;
    byte *key256;
    size_t key128Length = 0;
    size_t key192Length = 0;
    size_t key256Length = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10", 32, &key128, key128Length);
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f101112131415161718", 48, &key192, key192Length);
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f1011121314151617181901020304050607", 64, &key256, key256Length);

    // set/get keys
    size_t key0Length = cipher.getKeyLength();

    cipher.setKey(key128, key128Length);
    size_t key128GetLength = cipher.getKeyLength();
    byte key128Get[key128GetLength];
    cipher.getKey(key128Get);

    cipher.setKey(key192, key192Length);
    size_t key192GetLength = cipher.getKeyLength();
    byte key192Get[key192GetLength];
    cipher.getKey(key192Get);

    cipher.setKey(key256, key256Length);
    size_t key256GetLength = cipher.getKeyLength();
    byte key256Get[key256GetLength];
    cipher.getKey(key256Get);

    // test keys
    EXPECT_EQ(0, key0Length);
    EXPECT_BYTE_ARRAY_EQ(key128, key128Length, key128Get, key128GetLength);
    EXPECT_BYTE_ARRAY_EQ(key192, key192Length, key192Get, key192GetLength);
    EXPECT_BYTE_ARRAY_EQ(key256, key256Length, key256Get, key256GetLength);

    delete[] key128;
    delete[] key192;
    delete[] key256;
}

TEST(BlockCipherAesTest, encryptBlock) {
    CryptoppApi::BlockCipherAes cipher;
    size_t blockSize = cipher.getBlockSize();

    byte output1[blockSize];
    byte output2[blockSize];
    byte *expected1;
    byte *expected2;

    // build keys
    byte *key128;
    byte *key192;
    byte *key256;
    size_t key128Length = 0;
    size_t key192Length = 0;
    size_t key256Length = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key128, key128Length);
    CryptoppApi::HexUtils::hex2bin("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 48, &key192, key192Length);
    CryptoppApi::HexUtils::hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 64, &key256, key256Length);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172a", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("ae2d8a571e03ac9c9eb76fac45af8e51", 32, &block2, dummyLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("3ad77bb40d7a3660a89ecaf32466ef97", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("f5d3d58503b9699de785895a96fdbaaf", 32, &expected2, dummyLength);
    cipher.setKey(key128, key128Length);
    cipher.encryptBlock(block1, output1, blockSize);
    cipher.encryptBlock(block2, output2, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, blockSize, output1, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, blockSize, output2, blockSize);

    delete[] expected1;
    delete[] expected2;

    // aes192
    CryptoppApi::HexUtils::hex2bin("bd334f1d6e45f25ff712a214571fa5cc", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("974104846d0ad3ad7734ecb3ecee4eef", 32, &expected2, dummyLength);
    cipher.setKey(key192, key192Length);
    cipher.encryptBlock(block1, output1, blockSize);
    cipher.encryptBlock(block2, output2, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, blockSize, output1, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, blockSize, output2, blockSize);

    delete[] expected1;
    delete[] expected2;

    // aes256
    CryptoppApi::HexUtils::hex2bin("f3eed1bdb5d2a03c064b5a7e3db181f8", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("591ccb10d410ed26dc5ba74a31362870", 32, &expected2, dummyLength);
    cipher.setKey(key256, key256Length);
    cipher.encryptBlock(block1, output1, blockSize);
    cipher.encryptBlock(block2, output2, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, blockSize, output1, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, blockSize, output2, blockSize);

    delete[] expected1;
    delete[] expected2;

    delete[] key128;
    delete[] key192;
    delete[] key256;
    delete[] block1;
    delete[] block2;
}

TEST(BlockCipherAesTest, decryptBlock) {
    CryptoppApi::BlockCipherAes cipher;
    size_t blockSize = cipher.getBlockSize();

    byte output1[blockSize];
    byte output2[blockSize];
    byte *block1;
    byte *block2;

    // build keys
    byte *key128;
    byte *key192;
    byte *key256;
    size_t key128Length = 0;
    size_t key192Length = 0;
    size_t key256Length = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key128, key128Length);
    CryptoppApi::HexUtils::hex2bin("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 48, &key192, key192Length);
    CryptoppApi::HexUtils::hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 64, &key256, key256Length);

    // build expected data
    byte *expected1;
    byte *expected2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172a", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("ae2d8a571e03ac9c9eb76fac45af8e51", 32, &expected2, dummyLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("3ad77bb40d7a3660a89ecaf32466ef97", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("f5d3d58503b9699de785895a96fdbaaf", 32, &block2, dummyLength);
    cipher.setKey(key128, key128Length);
    cipher.decryptBlock(block1, output1, blockSize);
    cipher.decryptBlock(block2, output2, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, blockSize, output1, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, blockSize, output2, blockSize);

    delete[] block1;
    delete[] block2;

    // aes192
    CryptoppApi::HexUtils::hex2bin("bd334f1d6e45f25ff712a214571fa5cc", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("974104846d0ad3ad7734ecb3ecee4eef", 32, &block2, dummyLength);
    cipher.setKey(key192, key192Length);
    cipher.decryptBlock(block1, output1, blockSize);
    cipher.decryptBlock(block2, output2, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, blockSize, output1, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, blockSize, output2, blockSize);

    delete[] block1;
    delete[] block2;

    // aes256
    CryptoppApi::HexUtils::hex2bin("f3eed1bdb5d2a03c064b5a7e3db181f8", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("591ccb10d410ed26dc5ba74a31362870", 32, &block2, dummyLength);
    cipher.setKey(key256, key256Length);
    cipher.decryptBlock(block1, output1, blockSize);
    cipher.decryptBlock(block2, output2, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, blockSize, output1, blockSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, blockSize, output2, blockSize);

    delete[] block1;
    delete[] block2;

    delete[] key128;
    delete[] key192;
    delete[] key256;
    delete[] expected1;
    delete[] expected2;
}

TEST(BlockCipherAesTest, encrypt) {
    CryptoppApi::BlockCipherAes cipher;
    size_t dataSize = 32;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build keys
    byte *key128;
    byte *key192;
    byte *key256;
    size_t key128Length = 0;
    size_t key192Length = 0;
    size_t key256Length = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key128, key128Length);
    CryptoppApi::HexUtils::hex2bin("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 48, &key192, key192Length);
    CryptoppApi::HexUtils::hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 64, &key256, key256Length);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64, &block2, dummyLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4", 64, &expected2, dummyLength);
    cipher.setKey(key128, key128Length);
    cipher.encrypt(block1, output1, dataSize);
    cipher.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    // aes192
    CryptoppApi::HexUtils::hex2bin("bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e", 64, &expected2, dummyLength);
    cipher.setKey(key192, key192Length);
    cipher.encrypt(block1, output1, dataSize);
    cipher.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    // aes256
    CryptoppApi::HexUtils::hex2bin("f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7", 64, &expected2, dummyLength);
    cipher.setKey(key256, key256Length);
    cipher.encrypt(block1, output1, dataSize);
    cipher.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    delete[] key128;
    delete[] key192;
    delete[] key256;
    delete[] block1;
    delete[] block2;
}

TEST(BlockCipherAesTest, decrypt) {
    CryptoppApi::BlockCipherAes cipher;
    size_t dataSize = 32;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *block1;
    byte *block2;

    // build keys
    byte *key128;
    byte *key192;
    byte *key256;
    size_t key128Length = 0;
    size_t key192Length = 0;
    size_t key256Length = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key128, key128Length);
    CryptoppApi::HexUtils::hex2bin("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 48, &key192, key192Length);
    CryptoppApi::HexUtils::hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 64, &key256, key256Length);

    // build expected data
    byte *expected1;
    byte *expected2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64, &expected2, dummyLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4", 64, &block2, dummyLength);
    cipher.setKey(key128, key128Length);
    cipher.decrypt(block1, output1, dataSize);
    cipher.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;

    // aes192
    CryptoppApi::HexUtils::hex2bin("bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e", 64, &block2, dummyLength);
    cipher.setKey(key192, key192Length);
    cipher.decrypt(block1, output1, dataSize);
    cipher.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;

    // aes256
    CryptoppApi::HexUtils::hex2bin("f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7", 64, &block2, dummyLength);
    cipher.setKey(key256, key256Length);
    cipher.decrypt(block1, output1, dataSize);
    cipher.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;

    delete[] key128;
    delete[] key192;
    delete[] key256;
    delete[] expected1;
    delete[] expected2;
}

TEST(BlockCipherAesTest, largeData) {
    CryptoppApi::BlockCipherAes cipher;

    std::string key("1234567890123456");
    cipher.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    size_t dataSize = 10485760;
    byte *input     = new byte[dataSize];
    byte *output    = new byte[dataSize];
    cipher.encrypt(input, output, dataSize);
    cipher.decrypt(input, output, dataSize);

    delete[] input;
    delete[] output;
}

TEST(BlockCipherAesTest, cryptBlockInvalidBlockSize) {
    CryptoppApi::BlockCipherAes cipher;

    std::string key("1234567890123456");
    cipher.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    std::string dataStr("123456789");
    const byte *data    = reinterpret_cast<const byte*>(dataStr.c_str());
    size_t dataLength   = dataStr.length();
    byte output[dataLength];

    EXPECT_THROW_MSG(cipher.encryptBlock(data, output, dataLength), CryptoppApi::Exception, "data size (9) is not equal to cipher block size (16)");
    EXPECT_THROW_MSG(cipher.decryptBlock(data, output, dataLength), CryptoppApi::Exception, "data size (9) is not equal to cipher block size (16)");
}

TEST(BlockCipherAesTest, cryptInvalidBlockSize) {
    CryptoppApi::BlockCipherAes cipher;

    std::string key("1234567890123456");
    cipher.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    std::string dataStr("12345678901234567");
    const byte *data    = reinterpret_cast<const byte*>(dataStr.c_str());
    size_t dataLength   = dataStr.length();
    byte output[dataLength];

    EXPECT_THROW_MSG(cipher.encrypt(data, output, dataLength), CryptoppApi::Exception, "data size (17) is not a multiple of block size (16)");
    EXPECT_THROW_MSG(cipher.decrypt(data, output, dataLength), CryptoppApi::Exception, "data size (17) is not a multiple of block size (16)");
}

TEST(BlockCipherAesTest, invalidKey) {
    CryptoppApi::BlockCipherAes cipher;

    byte key1[] = {45, 12, 14};
    byte key2[0];

    EXPECT_THROW_MSG(cipher.setKey(key1, 3), CryptoppApi::Exception, "3 is not a valid key length");
    EXPECT_THROW_MSG(cipher.setKey(key2, 0), CryptoppApi::Exception, "a key is required");
}

TEST(BlockCipherAesTest, cryptWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;

    size_t inputLength = cipher.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(cipher.encrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(cipher.encryptBlock(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(cipher.decrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(cipher.decryptBlock(input, output, inputLength), CryptoppApi::Exception, "a key is required");
}
