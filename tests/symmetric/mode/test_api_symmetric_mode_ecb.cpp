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
#include "src/symmetric/mode/api_symmetric_mode_ecb.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(SymmetricModeEcbTest, inheritance) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricCipherInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricTransformationInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricModeInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricModeAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricIvAbstract*>(&mode));
}

TEST(SymmetricModeEcbTest, infos) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);

    EXPECT_STREQ("ecb(aes)", mode.getName());
    EXPECT_EQ(16, mode.getBlockSize());
}

TEST(SymmetricModeEcbTest, isValidKeyLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);

    EXPECT_TRUE(mode.isValidKeyLength(16));
    EXPECT_FALSE(mode.isValidKeyLength(15));
    EXPECT_FALSE(mode.isValidKeyLength(17));

    EXPECT_TRUE(mode.isValidKeyLength(24));
    EXPECT_FALSE(mode.isValidKeyLength(23));
    EXPECT_FALSE(mode.isValidKeyLength(25));

    EXPECT_TRUE(mode.isValidKeyLength(32));
    EXPECT_FALSE(mode.isValidKeyLength(31));
    EXPECT_FALSE(mode.isValidKeyLength(33));
}

TEST(SymmetricModeEcbTest, isValidIvLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);

    EXPECT_TRUE(mode.isValidIvLength(0));
    EXPECT_FALSE(mode.isValidKeyLength(1));
    EXPECT_FALSE(mode.isValidKeyLength(17));
}

TEST(SymmetricModeEcbTest, setGetKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);

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
    size_t key0Length = mode.getKeyLength();

    mode.setKey(key128, key128Length);
    size_t key128GetLength = mode.getKeyLength();
    byte key128Get[key128GetLength];
    mode.getKey(key128Get);

    mode.setKey(key192, key192Length);
    size_t key192GetLength = mode.getKeyLength();
    byte key192Get[key192GetLength];
    mode.getKey(key192Get);

    mode.setKey(key256, key256Length);
    size_t key256GetLength = mode.getKeyLength();
    byte key256Get[key256GetLength];
    mode.getKey(key256Get);

    // test keys
    EXPECT_EQ(0, key0Length);
    EXPECT_BYTE_ARRAY_EQ(key128, key128Length, key128Get, key128GetLength);
    EXPECT_BYTE_ARRAY_EQ(key192, key192Length, key192Get, key192GetLength);
    EXPECT_BYTE_ARRAY_EQ(key256, key256Length, key256Get, key256GetLength);

    delete[] key128;
    delete[] key192;
    delete[] key256;
}

TEST(SymmetricModeEcbTest, encrypt) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);
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
    mode.setKey(key128, key128Length);
    mode.encrypt(block1, output1, dataSize);
    mode.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    // aes192
    CryptoppApi::HexUtils::hex2bin("bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e", 64, &expected2, dummyLength);
    mode.setKey(key192, key192Length);
    mode.encrypt(block1, output1, dataSize);
    mode.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    // aes256
    CryptoppApi::HexUtils::hex2bin("f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7", 64, &expected2, dummyLength);
    mode.setKey(key256, key256Length);
    mode.encrypt(block1, output1, dataSize);
    mode.encrypt(block2, output2, dataSize);
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

TEST(SymmetricModeEcbTest, decrypt) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);
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
    mode.setKey(key128, key128Length);
    mode.decrypt(block1, output1, dataSize);
    mode.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;

    // aes192
    CryptoppApi::HexUtils::hex2bin("bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e", 64, &block2, dummyLength);
    mode.setKey(key192, key192Length);
    mode.decrypt(block1, output1, dataSize);
    mode.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;

    // aes256
    CryptoppApi::HexUtils::hex2bin("f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7", 64, &block2, dummyLength);
    mode.setKey(key256, key256Length);
    mode.decrypt(block1, output1, dataSize);
    mode.decrypt(block2, output2, dataSize);
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

TEST(SymmetricModeEcbTest, restartEncryption) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);
    size_t dataSize = 32;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key, keyLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4", 64, &expected2, dummyLength);
    mode.setKey(key, keyLength);
    mode.encrypt(block1, output1, dataSize);
    mode.restart();
    mode.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    delete[] key;
    delete[] block1;
    delete[] block2;
}

TEST(SymmetricModeEcbTest, restartDecryption) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);
    size_t dataSize = 32;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key, keyLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4", 64, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64, &expected2, dummyLength);
    mode.setKey(key, keyLength);
    mode.decrypt(block1, output1, dataSize);
    mode.restart();
    mode.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    delete[] key;
    delete[] block1;
    delete[] block2;
}

TEST(SymmetricModeEcbTest, largeData) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);

    std::string key("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    size_t dataSize = 10485760;
    byte *input     = new byte[dataSize];
    byte *output    = new byte[dataSize];
    memset(input, 125, dataSize);
    mode.encrypt(input, output, dataSize);
    mode.decrypt(input, output, dataSize);

    delete[] input;
    delete[] output;
}

TEST(SymmetricModeEcbTest, cryptInvalidBlockSize) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);

    std::string key("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    std::string dataStr("12345678901234567");
    const byte *data    = reinterpret_cast<const byte*>(dataStr.c_str());
    size_t dataLength   = dataStr.length();
    byte output[dataLength];

    EXPECT_THROW_MSG(mode.encrypt(data, output, dataLength), CryptoppApi::Exception, "data size (17) is not a multiple of block size (16)");
    EXPECT_THROW_MSG(mode.decrypt(data, output, dataLength), CryptoppApi::Exception, "data size (17) is not a multiple of block size (16)");
}

TEST(SymmetricModeEcbTest, invalidKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);

    byte key1[] = {45, 12, 14};
    byte key2[0];

    EXPECT_THROW_MSG(mode.setKey(key1, 3), CryptoppApi::Exception, "3 is not a valid key length");
    EXPECT_THROW_MSG(mode.setKey(key2, 0), CryptoppApi::Exception, "a key is required");
}

TEST(SymmetricModeEcbTest, invalidIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);

    byte iv[] = {45, 12, 14};

    EXPECT_THROW_MSG(mode.setIv(iv, 3), CryptoppApi::Exception, "3 is not a valid initialization vector length");
}

TEST(SymmetricModeEcbTest, cryptWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode(&cipher);

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
}

TEST(SymmetricModeEcbTest, keyNotMatchingUnderlyingOne) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeEcb mode1(&cipher);
    CryptoppApi::SymmetricModeEcb mode2(&cipher);

    std::string key1("1234567890123456");
    std::string key2("azertyuiopqwerty");
    std::string key3("wxcvbnqsdfghjklm");
    mode1.setKey(reinterpret_cast<const byte*>(key1.c_str()), key1.length());

    size_t inputLength = mode1.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    mode2.setKey(reinterpret_cast<const byte*>(key2.c_str()), key2.length());
    EXPECT_THROW_MSG(mode1.encrypt(input, output, inputLength), CryptoppApi::Exception, "key is not matching the one owned by the underlying cipher object");

    cipher.setKey(reinterpret_cast<const byte*>(key3.c_str()), key3.length());
    EXPECT_THROW_MSG(mode1.encrypt(input, output, inputLength), CryptoppApi::Exception, "key is not matching the one owned by the underlying cipher object");
}
