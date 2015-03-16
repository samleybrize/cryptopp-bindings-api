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
#include "src/symmetric/mode/api_symmetric_mode_ctr.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(SymmetricModeCtrTest, inheritance) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricCipherInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricTransformationInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricModeInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricModeAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricIvAbstract*>(&mode));
}

TEST(SymmetricModeCtrTest, infos) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

    EXPECT_STREQ("ctr(aes)", mode.getName());
    EXPECT_EQ(1, mode.getBlockSize());
}

TEST(SymmetricModeCtrTest, isValidKeyLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

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

TEST(SymmetricModeCtrTest, isValidIvLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

    EXPECT_TRUE(mode.isValidIvLength(16));
    EXPECT_FALSE(mode.isValidKeyLength(15));
    EXPECT_FALSE(mode.isValidKeyLength(17));
}

TEST(SymmetricModeCtrTest, setGetKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

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

TEST(SymmetricModeCtrTest, setGetIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

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

TEST(SymmetricModeCtrTest, encrypt) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);
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
    CryptoppApi::HexUtils::hex2bin("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64, &block2, dummyLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee", 64, &expected2, dummyLength);
    mode.setKey(key128, key128Length);
    mode.encrypt(block1, output1, dataSize);
    mode.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    // aes192
    CryptoppApi::HexUtils::hex2bin("1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("1e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050", 64, &expected2, dummyLength);
    mode.setKey(key192, key192Length);
    mode.encrypt(block1, output1, dataSize);
    mode.encrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] expected1;
    delete[] expected2;

    // aes256
    CryptoppApi::HexUtils::hex2bin("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6", 64, &expected2, dummyLength);
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

TEST(SymmetricModeCtrTest, decrypt) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);
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
    CryptoppApi::HexUtils::hex2bin("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build expected data
    byte *expected1;
    byte *expected2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64, &expected2, dummyLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee", 64, &block2, dummyLength);
    mode.setKey(key128, key128Length);
    mode.decrypt(block1, output1, dataSize);
    mode.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;

    // aes192
    CryptoppApi::HexUtils::hex2bin("1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("1e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050", 64, &block2, dummyLength);
    mode.setKey(key192, key192Length);
    mode.decrypt(block1, output1, dataSize);
    mode.decrypt(block2, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);

    delete[] block1;
    delete[] block2;

    // aes256
    CryptoppApi::HexUtils::hex2bin("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6", 64, &block2, dummyLength);
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

TEST(SymmetricModeCtrTest, restartEncryption) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);
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
    CryptoppApi::HexUtils::hex2bin("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", 64, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("dc44c3353b3c98a11729d76cf094f30bc0b45879b83cca74b58b36ac1a3c44be", 64, &expected2, dummyLength);
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

TEST(SymmetricModeCtrTest, restartDecryption) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);
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
    CryptoppApi::HexUtils::hex2bin("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee", 64, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("b668004d43b5afeea99d1f77e72e9f4f282861e648cd52b2618107770f50ef40", 64, &expected2, dummyLength);
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

TEST(SymmetricModeCtrTest, largeData) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

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

TEST(SymmetricModeCtrTest, isStream) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

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

TEST(SymmetricModeCtrTest, invalidKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

    byte key1[] = {45, 12, 14};
    byte key2[0];

    EXPECT_THROW_MSG(mode.setKey(key1, 3), CryptoppApi::Exception, "3 is not a valid key length");
    EXPECT_THROW_MSG(mode.setKey(key2, 0), CryptoppApi::Exception, "a key is required");
}

TEST(SymmetricModeCtrTest, invalidIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

    byte iv1[] = {45, 12, 14};
    byte iv2[0];

    EXPECT_THROW_MSG(mode.setIv(iv1, 3), CryptoppApi::Exception, "3 is not a valid initialization vector length");
    EXPECT_THROW_MSG(mode.setIv(iv2, 0), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(SymmetricModeCtrTest, cryptWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
}

TEST(SymmetricModeCtrTest, cryptWithoutIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode(&cipher);

    std::string key("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(SymmetricModeCtrTest, keyNotMatchingUnderlyingOne) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::SymmetricModeCtr mode1(&cipher);
    CryptoppApi::SymmetricModeCtr mode2(&cipher);

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
