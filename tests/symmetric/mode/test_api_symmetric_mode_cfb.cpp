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
#include "src/symmetric/mode/api_symmetric_mode_cfb.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(SymmetricModeCfbTest, inheritance) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricCipherInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricTransformationInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricModeInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricModeAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricIvAbstract*>(&mode));
}

TEST(SymmetricModeCfbTest, infos) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

    EXPECT_STREQ("cfb(aes)", mode.getName());
    EXPECT_EQ(1, mode.getBlockSize());
}

TEST(SymmetricModeCfbTest, isValidKeyLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

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

TEST(SymmetricModeCfbTest, isValidIvLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

    EXPECT_TRUE(mode.isValidIvLength(16));
    EXPECT_FALSE(mode.isValidKeyLength(15));
    EXPECT_FALSE(mode.isValidKeyLength(17));
}

TEST(SymmetricModeCfbTest, setGetKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

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

TEST(SymmetricModeCfbTest, setGetIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f10", 32, &iv, ivLength);

    // set/get iv
    size_t iv0Length = mode.getIvLength();

    mode.setIv(iv, ivLength);
    size_t ivGetLength = mode.getIvLength();
    byte ivGet[ivGetLength];
    mode.getIv(ivGet);

    // test ivs
    EXPECT_EQ(0, iv0Length);
    EXPECT_BYTE_ARRAY_EQ(iv, ivLength, ivGet, ivGetLength);

    delete[] iv;
}

TEST(SymmetricModeCfbTest, encrypt) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);
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

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64, &block2, dummyLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6", 64, &expected2, dummyLength);
    mode.setKey(key128, key128Length);
    mode.encrypt(block1, output1, dataSize);
    mode.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    // aes192
    CryptoppApi::HexUtils::hex2bin("cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff", 64, &expected2, dummyLength);
    mode.setKey(key192, key192Length);
    mode.encrypt(block1, output1, dataSize);
    mode.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    // aes256
    CryptoppApi::HexUtils::hex2bin("dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407b", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("df10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471", 64, &expected2, dummyLength);
    mode.setKey(key256, key256Length);
    mode.encrypt(block1, output1, dataSize);
    mode.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    delete[] iv;
    delete[] key128;
    delete[] key192;
    delete[] key256;
    delete[] block1;
    delete[] block2;
}

TEST(SymmetricModeCfbTest, decrypt) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);
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

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build expected data
    byte *expected1;
    byte *expected2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64, &expected2, dummyLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6", 64, &block2, dummyLength);
    mode.setKey(key128, key128Length);
    mode.decrypt(block1, output1, dataSize);
    mode.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;

    // aes192
    CryptoppApi::HexUtils::hex2bin("cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff", 64, &block2, dummyLength);
    mode.setKey(key192, key192Length);
    mode.decrypt(block1, output1, dataSize);
    mode.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;

    // aes256
    CryptoppApi::HexUtils::hex2bin("dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407b", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("df10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471", 64, &block2, dummyLength);
    mode.setKey(key256, key256Length);
    mode.decrypt(block1, output1, dataSize);
    mode.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;

    delete[] iv;
    delete[] key128;
    delete[] key192;
    delete[] key256;
    delete[] expected1;
    delete[] expected2;
}

TEST(SymmetricModeCfbTest, restartEncryption) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);
    size_t dataSize = 32;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("60367b8a3a31d6a73ff2f6f081a5be8f6c01b8a6e488e0e862c412c6f630ca52", 64, &expected2, dummyLength);
    mode.setKey(key, keyLength);
    mode.encrypt(block1, output1, dataSize);
    mode.restart();
    mode.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    delete[] key;
    delete[] iv;
    delete[] block1;
    delete[] block2;
}

TEST(SymmetricModeCfbTest, restartDecryption) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);
    size_t dataSize = 32;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2b7e151628aed2a6abf7158809cf4f3c", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("000102030405060708090a0b0c0d0e0f", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6", 64, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("768b78ab3aa683f66b89bb181c0b18bff69f2445df4f9b17ad2b417be66c3710", 64, &expected2, dummyLength);
    mode.setKey(key, keyLength);
    mode.decrypt(block1, output1, dataSize);
    mode.restart();
    mode.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    delete[] key;
    delete[] iv;
    delete[] block1;
    delete[] block2;
}

TEST(SymmetricModeCfbTest, largeData) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

    std::string key("1234567890123456");
    std::string iv("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    mode.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    size_t dataSize = 10485760;
    byte *input     = new byte[dataSize];
    byte *output    = new byte[dataSize];
    memset(input, 125, dataSize);
    mode.encrypt(input, output, dataSize);
    mode.decrypt(input, output, dataSize);

    delete[] input;
    delete[] output;
}

TEST(SymmetricModeCfbTest, isStream) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

    std::string key("1234567890123456");
    std::string iv("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    mode.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    std::string dataStr("12345678901234567");
    const byte *data    = reinterpret_cast<const byte*>(dataStr.c_str());
    size_t dataLength   = dataStr.length();
    byte output[dataLength];

    mode.encrypt(data, output, dataLength);
    mode.decrypt(data, output, dataLength);
}

TEST(SymmetricModeCfbTest, invalidKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

    byte key1[] = {45, 12, 14};
    byte key2[0];

    EXPECT_THROW_MSG(mode.setKey(key1, 3), CryptoppApi::Exception, "3 is not a valid key length");
    EXPECT_THROW_MSG(mode.setKey(key2, 0), CryptoppApi::Exception, "a key is required");
}

TEST(SymmetricModeCfbTest, invalidIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

    byte iv1[] = {45, 12, 14};
    byte iv2[0];

    EXPECT_THROW_MSG(mode.setIv(iv1, 3), CryptoppApi::Exception, "3 is not a valid initialization vector length");
    EXPECT_THROW_MSG(mode.setIv(iv2, 0), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(SymmetricModeCfbTest, cryptWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
}

TEST(SymmetricModeCfbTest, cryptWithoutIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode(&cipher);

    std::string key("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(SymmetricModeCfbTest, keyNotMatchingUnderlyingOne) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCfb mode1(&cipher);
    CryptoppApi::SymmetricModeCfb mode2(&cipher);

    std::string iv("1234567890123456");
    mode1.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

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
