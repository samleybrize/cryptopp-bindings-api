/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/symmetric/cipher/authenticated/api_authenticated_symmetric_cipher_gcm.h"
#include "src/symmetric/cipher/block/api_block_cipher_aes.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(AuthenticatedSymmetricCipherGcmTest, inheritance) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricCipherInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricTransformationInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::AuthenticatedSymmetricCipherInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::AuthenticatedSymmetricCipherAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricIvAbstract*>(&mode));
}

TEST(AuthenticatedSymmetricCipherGcmTest, infos) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

    EXPECT_STREQ("gcm(aes)", mode.getName());
    EXPECT_EQ(1, mode.getBlockSize());
    EXPECT_EQ(16, mode.getDigestSize());
}

TEST(AuthenticatedSymmetricCipherGcmTest, isValidKeyLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

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

TEST(AuthenticatedSymmetricCipherGcmTest, isValidIvLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

    EXPECT_FALSE(mode.isValidKeyLength(0));
    EXPECT_TRUE(mode.isValidIvLength(2));
    EXPECT_TRUE(mode.isValidIvLength(4));
    EXPECT_TRUE(mode.isValidIvLength(56));
    EXPECT_TRUE(mode.isValidIvLength(1256));
}

TEST(AuthenticatedSymmetricCipherGcmTest, setGetKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

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

TEST(AuthenticatedSymmetricCipherGcmTest, setGetIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

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

TEST(AuthenticatedSymmetricCipherGcmTest, encrypt) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);
    size_t dataSize     = 32;
    size_t digestSize   = mode.getDigestSize();

    byte output1[dataSize];
    byte output2[dataSize];
    byte output3[digestSize];
    byte *expected1;
    byte *expected2;
    byte *expected3;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("cafebabefacedbaddecaf888", 24, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", 64, &block2, dummyLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", 64, &expected2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("4d5c2af327cd64a62cf35abd2ba6fab4", 32, &expected3, dummyLength);
    mode.setKey(key, keyLength);
    mode.encrypt(block1, output1, dataSize);
    mode.encrypt(block2, output2, dataSize);
    mode.finalizeEncryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestSize, output3, digestSize);

    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
    delete[] iv;
    delete[] key;
    delete[] block1;
    delete[] block2;
}

TEST(AuthenticatedSymmetricCipherGcmTest, decrypt) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);
    size_t dataSize     = 32;
    size_t digestSize   = mode.getDigestSize();

    byte output1[dataSize];
    byte output2[dataSize];
    byte output3[digestSize];
    byte *block1;
    byte *block2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("cafebabefacedbaddecaf888", 24, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build expected data
    byte *expected1;
    byte *expected2;
    byte *expected3;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", 64, &expected2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("4d5c2af327cd64a62cf35abd2ba6fab4", 32, &expected3, dummyLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", 64, &block2, dummyLength);
    mode.setKey(key, keyLength);
    mode.decrypt(block1, output1, dataSize);
    mode.decrypt(block2, output2, dataSize);
    mode.finalizeDecryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestSize, output3, digestSize);

    delete[] block1;
    delete[] block2;
    delete[] iv;
    delete[] key;
    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
}

TEST(AuthenticatedSymmetricCipherGcmTest, restartEncryption) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);
    size_t dataSize     = 32;
    size_t digestSize   = mode.getDigestSize();

    byte output1[dataSize];
    byte output2[dataSize];
    byte output3[digestSize];
    byte *expected1;
    byte *expected2;
    byte *expected3;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("cafebabefacedbaddecaf888", 24, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72", 64, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e", 64, &expected2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("67383e3899332afdd4d83a204575a052", 32, &expected3, dummyLength);
    mode.setKey(key, keyLength);
    mode.encrypt(block1, output1, dataSize);
    mode.restart();
    mode.encrypt(block2, output2, dataSize);
    mode.finalizeEncryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestSize, output3, digestSize);

    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
    delete[] key;
    delete[] iv;
    delete[] block1;
    delete[] block2;
}

TEST(AuthenticatedSymmetricCipherGcmTest, restartDecryption) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);
    size_t dataSize     = 32;
    size_t digestSize   = mode.getDigestSize();

    byte output1[dataSize];
    byte output2[dataSize];
    byte output3[digestSize];
    byte *expected1;
    byte *expected2;
    byte *expected3;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("cafebabefacedbaddecaf888", 24, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e", 64, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72", 64, &expected2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("67383e3899332afdd4d83a204575a052", 32, &expected3, dummyLength);
    mode.setKey(key, keyLength);
    mode.decrypt(block1, output1, dataSize);
    mode.restart();
    mode.decrypt(block2, output2, dataSize);
    mode.finalizeDecryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, dataSize, output1, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, dataSize, output2, dataSize);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestSize, output3, digestSize);

    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
    delete[] key;
    delete[] iv;
    delete[] block1;
    delete[] block2;
}

TEST(AuthenticatedSymmetricCipherGcmTest, encryptWithAad) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);
    size_t dataSize     = 32;
    size_t digestSize   = mode.getDigestSize();

    byte output1[dataSize];
    byte output2[dataSize];
    byte output3[digestSize];
    byte *expected1;
    byte *expected2;
    byte *expected3;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("cafebabefacedbaddecaf888", 24, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    byte *aad;
    size_t dummyLength  = 0;
    size_t block1Length = 0;
    size_t block2Length = 0;
    size_t aadLength    = 0;
    CryptoppApi::HexUtils::hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72", 64, &block1, block1Length);
    CryptoppApi::HexUtils::hex2bin("1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 56, &block2, block2Length);
    CryptoppApi::HexUtils::hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", 40, &aad, aadLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e", 64, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", 56, &expected2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("5bc94fbc3221a5db94fae95ae7121a47", 32, &expected3, dummyLength);
    mode.setKey(key, keyLength);
    mode.addEncryptionAdditionalData(aad, aadLength);
    mode.encrypt(block1, output1, block1Length);
    mode.encrypt(block2, output2, block2Length);
    mode.finalizeEncryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, block1Length, output1, block1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, block2Length, output2, block2Length);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestSize, output3, digestSize);

    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
    delete[] iv;
    delete[] key;
    delete[] block1;
    delete[] block2;
    delete[] aad;
}

TEST(AuthenticatedSymmetricCipherGcmTest, decryptWithAad) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);
    size_t dataSize     = 32;
    size_t digestSize   = mode.getDigestSize();

    byte output1[dataSize];
    byte output2[dataSize];
    byte output3[digestSize];
    byte *block1;
    byte *block2;
    byte *aad;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("cafebabefacedbaddecaf888", 24, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build expected data
    byte *expected1;
    byte *expected2;
    byte *expected3;
    size_t dummyLength      = 0;
    size_t expected1Length  = 0;
    size_t expected2Length  = 0;
    CryptoppApi::HexUtils::hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72", 64, &expected1, expected1Length);
    CryptoppApi::HexUtils::hex2bin("1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 56, &expected2, expected2Length);
    CryptoppApi::HexUtils::hex2bin("5bc94fbc3221a5db94fae95ae7121a47", 32, &expected3, dummyLength);

    // aes128
    size_t aadLength = 0;
    CryptoppApi::HexUtils::hex2bin("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e", 64, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", 56, &block2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", 40, &aad, aadLength);
    mode.setKey(key, keyLength);
    mode.addDecryptionAdditionalData(aad, aadLength);
    mode.decrypt(block1, output1, expected1Length);
    mode.decrypt(block2, output2, expected2Length);
    mode.finalizeDecryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, expected1Length, output1, expected1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, expected2Length, output2, expected2Length);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestSize, output3, digestSize);

    delete[] block1;
    delete[] block2;
    delete[] aad;
    delete[] iv;
    delete[] key;
    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
}

TEST(AuthenticatedSymmetricCipherGcmTest, encryptAadOnly) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);
    size_t digestSize = mode.getDigestSize();

    byte output[digestSize];
    byte *expected;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("77be63708971c4e240d1cb79e8d77feb", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("e0e00f19fed7ba0136a797f3", 24, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build aad
    byte *aad;
    size_t aadLength = 0;
    CryptoppApi::HexUtils::hex2bin("7a43ec1d9c0a5a78a0b16533a6213cab", 32, &aad, aadLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("209fcc8d3675ed938e9c7166709dd946", 32, &expected, digestSize);
    mode.setKey(key, keyLength);
    mode.addEncryptionAdditionalData(aad, aadLength);
    mode.finalizeEncryption(output);
    EXPECT_BYTE_ARRAY_EQ(expected, digestSize, output, digestSize);

    delete[] expected;
    delete[] iv;
    delete[] key;
    delete[] aad;
}

TEST(AuthenticatedSymmetricCipherGcmTest, decryptAadOnly) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);
    size_t digestSize = mode.getDigestSize();

    byte output[digestSize];
    byte *expected;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("77be63708971c4e240d1cb79e8d77feb", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("e0e00f19fed7ba0136a797f3", 24, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build aad
    byte *aad;
    size_t aadLength = 0;
    CryptoppApi::HexUtils::hex2bin("7a43ec1d9c0a5a78a0b16533a6213cab", 32, &aad, aadLength);

    // aes128
    CryptoppApi::HexUtils::hex2bin("209fcc8d3675ed938e9c7166709dd946", 32, &expected, digestSize);
    mode.setKey(key, keyLength);
    mode.addDecryptionAdditionalData(aad, aadLength);
    mode.finalizeDecryption(output);
    EXPECT_BYTE_ARRAY_EQ(expected, digestSize, output, digestSize);

    delete[] expected;
    delete[] iv;
    delete[] key;
    delete[] aad;
}

TEST(AuthenticatedSymmetricCipherGcmTest, largeData) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

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

TEST(AuthenticatedSymmetricCipherGcmTest, isStream) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

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

TEST(AuthenticatedSymmetricCipherGcmTest, invalidKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

    byte key1[] = {45, 12, 14};
    byte key2[0];

    EXPECT_THROW_MSG(mode.setKey(key1, 3), CryptoppApi::Exception, "3 is not a valid key length");
    EXPECT_THROW_MSG(mode.setKey(key2, 0), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherGcmTest, invalidIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

    byte iv[0];
    EXPECT_THROW_MSG(mode.setIv(iv, 0), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(AuthenticatedSymmetricCipherGcmTest, cryptWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherGcmTest, cryptWithoutIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

    std::string key("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(AuthenticatedSymmetricCipherGcmTest, cryptAadWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

    byte input[10];

    EXPECT_THROW_MSG(mode.addEncryptionAdditionalData(input, 10), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.addDecryptionAdditionalData(input, 10), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherGcmTest, finalizeWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

    byte output[mode.getDigestSize()];

    EXPECT_THROW_MSG(mode.finalizeEncryption(output), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.finalizeDecryption(output), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherGcmTest, cryptBeforeAad) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode(&cipher);

    std::string key("1234567890123456");
    std::string iv("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    mode.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    mode.encrypt(input, output, inputLength);
    mode.decrypt(input, output, inputLength);

    EXPECT_THROW_MSG(mode.addEncryptionAdditionalData(input, inputLength), CryptoppApi::Exception, "additional authenticated data must be added before any encryption");
    EXPECT_THROW_MSG(mode.addDecryptionAdditionalData(input, inputLength), CryptoppApi::Exception, "additional authenticated data must be added before any decryption");
}

TEST(AuthenticatedSymmetricCipherGcmTest, keyNotMatchingUnderlyingOne) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode1(&cipher);
    CryptoppApi::AuthenticatedSymmetricCipherGcm mode2(&cipher);

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
