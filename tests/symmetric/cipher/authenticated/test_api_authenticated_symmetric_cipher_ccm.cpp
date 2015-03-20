/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/symmetric/cipher/authenticated/api_authenticated_symmetric_cipher_ccm.h"
#include "src/symmetric/cipher/block/api_block_cipher_aes.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(AuthenticatedSymmetricCipherCcmTest, inheritance) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricCipherInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricTransformationInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::AuthenticatedSymmetricCipherInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::AuthenticatedSymmetricCipherAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricIvAbstract*>(&mode));
}

TEST(AuthenticatedSymmetricCipherCcmTest, infos) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    EXPECT_STREQ("ccm(aes)", mode.getName());
    EXPECT_EQ(1, mode.getBlockSize());
    EXPECT_EQ(16, mode.getDigestSize());
}

TEST(AuthenticatedSymmetricCipherCcmTest, isValidKeyLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

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

TEST(AuthenticatedSymmetricCipherCcmTest, isValidIvLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    EXPECT_FALSE(mode.isValidIvLength(0));
    EXPECT_FALSE(mode.isValidIvLength(2));
    EXPECT_TRUE(mode.isValidIvLength(7));
    EXPECT_TRUE(mode.isValidIvLength(13));
    EXPECT_FALSE(mode.isValidIvLength(15));
}

TEST(AuthenticatedSymmetricCipherCcmTest, setGetKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

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

TEST(AuthenticatedSymmetricCipherCcmTest, setGetIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d", 26, &iv, ivLength);

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

TEST(AuthenticatedSymmetricCipherCcmTest, encrypt) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00000003020100a0a1a2a3a4a5", 26, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t block1Length = 0;
    size_t block2Length = 0;
    CryptoppApi::HexUtils::hex2bin("08090a0b0c0d0e0f101112", 22, &block1, block1Length);
    CryptoppApi::HexUtils::hex2bin("131415161718191a1b1c1d1e", 24, &block2, block2Length);

    // aes128
    size_t digestLength = 0;
    byte *expected1;
    byte *expected2;
    byte *expected3;

    CryptoppApi::HexUtils::hex2bin("588c979a61c663d2f066d0", 22, &expected1, block1Length);
    CryptoppApi::HexUtils::hex2bin("c2c0f989806d5f6b61dac384", 24, &expected2, block2Length);
    CryptoppApi::HexUtils::hex2bin("7c2051a7ae200bcf", 16, &expected3, digestLength);

    byte output1[block1Length];
    byte output2[block2Length];
    byte output3[digestLength];

    mode.setDigestSize(digestLength);
    mode.specifyDataSize(23, 0);
    mode.setKey(key, keyLength);
    mode.encrypt(block1, output1, block1Length);
    mode.encrypt(block2, output2, block2Length);
    mode.finalizeEncryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, block1Length, output1, block1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, block2Length, output2, block2Length);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestLength, output3, digestLength);

    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
    delete[] iv;
    delete[] key;
    delete[] block1;
    delete[] block2;
}

TEST(AuthenticatedSymmetricCipherCcmTest, decrypt) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00000003020100a0a1a2a3a4a5", 26, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build expected data
    byte *expected1;
    byte *expected2;
    byte *expected3;
    size_t block1Length = 0;
    size_t block2Length = 0;
    size_t digestLength = 0;
    CryptoppApi::HexUtils::hex2bin("08090a0b0c0d0e0f101112", 22, &expected1, block1Length);
    CryptoppApi::HexUtils::hex2bin("131415161718191a1b1c1d1e", 24, &expected2, block2Length);
    CryptoppApi::HexUtils::hex2bin("7c2051a7ae200bcf", 16, &expected3, digestLength);

    // aes128
    byte *block1;
    byte *block2;
    byte output1[block1Length];
    byte output2[block2Length];
    byte output3[digestLength];
    CryptoppApi::HexUtils::hex2bin("588c979a61c663d2f066d0", 22, &block1, block1Length);
    CryptoppApi::HexUtils::hex2bin("c2c0f989806d5f6b61dac384", 24, &block2, block2Length);

    mode.setDigestSize(digestLength);
    mode.specifyDataSize(23, 0);
    mode.setKey(key, keyLength);
    mode.decrypt(block1, output1, block1Length);
    mode.decrypt(block2, output2, block2Length);
    mode.finalizeDecryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, block1Length, output1, block1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, block2Length, output2, block2Length);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestLength, output3, digestLength);

    delete[] block1;
    delete[] block2;
    delete[] iv;
    delete[] key;
    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
}

TEST(AuthenticatedSymmetricCipherCcmTest, restartEncryption) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00000003020100a0a1a2a3a4a5", 26, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t block1Length = 0;
    size_t block2Length = 0;
    CryptoppApi::HexUtils::hex2bin("08090a0b0c0d0e0f101112", 22, &block1, block1Length);
    CryptoppApi::HexUtils::hex2bin("131415161718191a1b1c1d1e", 24, &block2, block2Length);

    // calculate actual data
    size_t digestLength = 0;
    byte *expected1;
    byte *expected2;
    byte *expected3;
    CryptoppApi::HexUtils::hex2bin("588c979a61c663d2f066d0", 22, &expected1, block1Length);
    CryptoppApi::HexUtils::hex2bin("439188877ad374c7fb6bdfcf", 24, &expected2, block2Length);
    CryptoppApi::HexUtils::hex2bin("e8599abbfb0fa24247ceb346d0e68532", 32, &expected3, digestLength);

    byte output1[block1Length];
    byte output2[block2Length];
    byte output3[digestLength];

    mode.setKey(key, keyLength);
    mode.specifyDataSize(11, 0);
    mode.encrypt(block1, output1, block1Length);
    mode.restart();
    mode.specifyDataSize(12, 0);
    mode.encrypt(block2, output2, block2Length);
    mode.finalizeEncryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, block1Length, output1, block1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, block2Length, output2, block2Length);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestLength, output3, digestLength);

    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
    delete[] key;
    delete[] iv;
    delete[] block1;
    delete[] block2;
}

TEST(AuthenticatedSymmetricCipherCcmTest, restartDecryption) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00000003020100a0a1a2a3a4a5", 26, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t block1Length = 0;
    size_t block2Length = 0;
    size_t digestLength = 0;
    CryptoppApi::HexUtils::hex2bin("588c979a61c663d2f066d0", 22, &block1, block1Length);
    CryptoppApi::HexUtils::hex2bin("c2c0f989806d5f6b61dac384", 24, &block2, block2Length);

    // calculate actual data
    byte *expected1;
    byte *expected2;
    byte *expected3;
    CryptoppApi::HexUtils::hex2bin("08090a0b0c0d0e0f101112", 22, &expected1, block1Length);
    CryptoppApi::HexUtils::hex2bin("92456418eda632b681ad0155", 24, &expected2, block2Length);
    CryptoppApi::HexUtils::hex2bin("dab641c7493a27b8127514bd5f423b23", 32, &expected3, digestLength);

    byte output1[block1Length];
    byte output2[block2Length];
    byte output3[digestLength];

    mode.setKey(key, keyLength);
    mode.specifyDataSize(11, 0);
    mode.decrypt(block1, output1, block1Length);
    mode.restart();
    mode.specifyDataSize(12, 0);
    mode.decrypt(block2, output2, block2Length);
    mode.finalizeDecryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, block1Length, output1, block1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, block2Length, output2, block2Length);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestLength, output3, digestLength);

    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
    delete[] key;
    delete[] iv;
    delete[] block1;
    delete[] block2;
}

TEST(AuthenticatedSymmetricCipherCcmTest, encryptWithAad) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00000003020100a0a1a2a3a4a5", 26, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    byte *aad;
    size_t block1Length = 0;
    size_t block2Length = 0;
    size_t aadLength    = 0;
    CryptoppApi::HexUtils::hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72", 64, &block1, block1Length);
    CryptoppApi::HexUtils::hex2bin("1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 56, &block2, block2Length);
    CryptoppApi::HexUtils::hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", 40, &aad, aadLength);

    // aes128
    byte *expected1;
    byte *expected2;
    byte *expected3;
    size_t digestLength = 0;
    CryptoppApi::HexUtils::hex2bin("89b4afb4954f6b38452ecb147b19b90df3e1d829d3ea6d254a40ac3b545c87fd", 64, &expected1, block1Length);
    CryptoppApi::HexUtils::hex2bin("021e99bf795762d89d611c7bbe452d49ddde077fff1c34366f875232", 56, &expected2, block2Length);
    CryptoppApi::HexUtils::hex2bin("fc738cbb02a4a7a8972fc20d", 24, &expected3, digestLength);

    byte output1[block1Length];
    byte output2[block2Length];
    byte output3[digestLength];

    mode.setKey(key, keyLength);
    mode.specifyDataSize(60, 20);
    mode.setDigestSize(digestLength);
    mode.addEncryptionAdditionalData(aad, aadLength);
    mode.encrypt(block1, output1, block1Length);
    mode.encrypt(block2, output2, block2Length);
    mode.finalizeEncryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, block1Length, output1, block1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, block2Length, output2, block2Length);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestLength, output3, digestLength);

    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
    delete[] iv;
    delete[] key;
    delete[] block1;
    delete[] block2;
    delete[] aad;
}

TEST(AuthenticatedSymmetricCipherCcmTest, decryptWithAad) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", 32, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00000003020100a0a1a2a3a4a5", 26, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build expected data
    byte *expected1;
    byte *expected2;
    byte *expected3;
    size_t block1Length = 0;
    size_t block2Length = 0;
    size_t digestLength = 0;
    CryptoppApi::HexUtils::hex2bin("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72", 64, &expected1, block1Length);
    CryptoppApi::HexUtils::hex2bin("1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 56, &expected2, block2Length);
    CryptoppApi::HexUtils::hex2bin("fc738cbb02a4a7a8972fc20d", 24, &expected3, digestLength);

    // aes128
    size_t aadLength = 0;
    byte *block1;
    byte *block2;
    byte *aad;
    CryptoppApi::HexUtils::hex2bin("89b4afb4954f6b38452ecb147b19b90df3e1d829d3ea6d254a40ac3b545c87fd", 64, &block1, block1Length);
    CryptoppApi::HexUtils::hex2bin("021e99bf795762d89d611c7bbe452d49ddde077fff1c34366f875232", 56, &block2, block2Length);
    CryptoppApi::HexUtils::hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", 40, &aad, aadLength);

    byte output1[block1Length];
    byte output2[block2Length];
    byte output3[digestLength];

    mode.setKey(key, keyLength);
    mode.specifyDataSize(60, 20);
    mode.setDigestSize(digestLength);
    mode.addDecryptionAdditionalData(aad, aadLength);
    mode.decrypt(block1, output1, block1Length);
    mode.decrypt(block2, output2, block2Length);
    mode.finalizeDecryption(output3);
    EXPECT_BYTE_ARRAY_EQ(expected1, block1Length, output1, block1Length);
    EXPECT_BYTE_ARRAY_EQ(expected2, block2Length, output2, block2Length);
    EXPECT_BYTE_ARRAY_EQ(expected3, digestLength, output3, digestLength);

    delete[] block1;
    delete[] block2;
    delete[] aad;
    delete[] iv;
    delete[] key;
    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
}

TEST(AuthenticatedSymmetricCipherCcmTest, encryptAadOnly) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

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
    size_t digestLength = 0;
    byte *expected;
    CryptoppApi::HexUtils::hex2bin("b07790c26ada0c6b28576fc70234", 28, &expected, digestLength);

    byte output[digestLength];

    mode.setKey(key, keyLength);
    mode.setDigestSize(digestLength);
    mode.specifyDataSize(0, aadLength);
    mode.addEncryptionAdditionalData(aad, aadLength);
    mode.finalizeEncryption(output);
    EXPECT_BYTE_ARRAY_EQ(expected, digestLength, output, digestLength);

    delete[] expected;
    delete[] iv;
    delete[] key;
    delete[] aad;
}

TEST(AuthenticatedSymmetricCipherCcmTest, decryptAadOnly) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

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
    size_t digestLength = 0;
    byte *expected;
    CryptoppApi::HexUtils::hex2bin("b07790c26ada0c6b28576fc70234", 28, &expected, digestLength);

    byte output[digestLength];

    mode.setKey(key, keyLength);
    mode.setDigestSize(digestLength);
    mode.specifyDataSize(0, aadLength);
    mode.addDecryptionAdditionalData(aad, aadLength);
    mode.finalizeDecryption(output);
    EXPECT_BYTE_ARRAY_EQ(expected, digestLength, output, digestLength);

    delete[] expected;
    delete[] iv;
    delete[] key;
    delete[] aad;
}

TEST(AuthenticatedSymmetricCipherCcmTest, largeData) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    std::string key("1234567890123456");
    std::string iv("123456789012");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    mode.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    size_t dataSize = 10485760;
    byte *input     = new byte[dataSize];
    byte *output    = new byte[dataSize];
    memset(input, 125, dataSize);
    mode.specifyDataSize(dataSize, dataSize);
    mode.addEncryptionAdditionalData(input, dataSize);
    mode.addDecryptionAdditionalData(input, dataSize);
    mode.encrypt(input, output, dataSize);
    mode.decrypt(input, output, dataSize);

    delete[] input;
    delete[] output;
}

TEST(AuthenticatedSymmetricCipherCcmTest, badSpecifiedLength) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    std::string key("1234567890123456");
    std::string iv("123456789012");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    mode.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    std::string dataStr("12345678901234567");
    std::string data2Str("1234567890");
    const byte *data    = reinterpret_cast<const byte*>(dataStr.c_str());
    const byte *data2   = reinterpret_cast<const byte*>(data2Str.c_str());
    size_t dataLength   = dataStr.length();
    size_t data2Length  = data2Str.length();
    byte output[dataLength];

    mode.specifyDataSize(data2Length, data2Length);
    EXPECT_THROW_MSG(mode.addEncryptionAdditionalData(data, dataLength), CryptoppApi::Exception, "AAD length doesn't match that given in specifyDataSize (10 expected, 17 given)");
    EXPECT_THROW_MSG(mode.addDecryptionAdditionalData(data, dataLength), CryptoppApi::Exception, "AAD length doesn't match that given in specifyDataSize (10 expected, 17 given)");

    mode.restart();
    mode.addEncryptionAdditionalData(data2, data2Length);
    mode.addDecryptionAdditionalData(data2, data2Length);
    EXPECT_THROW_MSG(mode.encrypt(data, output, dataLength), CryptoppApi::Exception, "message length doesn't match that given in specifyDataSize (10 expected, 17 given)");
    EXPECT_THROW_MSG(mode.decrypt(data, output, dataLength), CryptoppApi::Exception, "message length doesn't match that given in specifyDataSize (10 expected, 17 given)");
}

TEST(AuthenticatedSymmetricCipherCcmTest, invalidKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    byte key1[] = {45, 12, 14};
    byte key2[0];

    EXPECT_THROW_MSG(mode.setKey(key1, 3), CryptoppApi::Exception, "3 is not a valid key length");
    EXPECT_THROW_MSG(mode.setKey(key2, 0), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherCcmTest, invalidIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    byte iv[0];
    EXPECT_THROW_MSG(mode.setIv(iv, 0), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(AuthenticatedSymmetricCipherCcmTest, cryptWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];
    mode.specifyDataSize(inputLength, 0);

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherCcmTest, cryptWithoutIv) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    std::string key("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];
    mode.specifyDataSize(inputLength, 0);

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(AuthenticatedSymmetricCipherCcmTest, cryptAadWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    byte input[10];
    mode.specifyDataSize(0, 10);

    EXPECT_THROW_MSG(mode.addEncryptionAdditionalData(input, 10), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.addDecryptionAdditionalData(input, 10), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherCcmTest, finalizeWithoutKey) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    byte output[mode.getDigestSize()];

    EXPECT_THROW_MSG(mode.finalizeEncryption(output), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.finalizeDecryption(output), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherCcmTest, cryptBeforeAad) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode(&cipher);

    std::string key("1234567890123456");
    std::string iv("123456789012");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    mode.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];
    mode.specifyDataSize(inputLength, inputLength);

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "AAD length doesn't match that given in specifyDataSize (1 expected, 0 given)");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "AAD length doesn't match that given in specifyDataSize (1 expected, 0 given)");
}

TEST(AuthenticatedSymmetricCipherCcmTest, keyNotMatchingUnderlyingOne) {
    CryptoppApi::BlockCipherAes cipher;
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode1(&cipher);
    CryptoppApi::AuthenticatedSymmetricCipherCcm mode2(&cipher);

    std::string iv("123456789012");
    mode1.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    std::string key1("1234567890123456");
    std::string key2("azertyuiopqwerty");
    std::string key3("wxcvbnqsdfghjklm");
    mode1.setKey(reinterpret_cast<const byte*>(key1.c_str()), key1.length());

    size_t inputLength = mode1.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];
    mode1.specifyDataSize(inputLength, 0);
    mode2.specifyDataSize(inputLength, 0);

    mode2.setKey(reinterpret_cast<const byte*>(key2.c_str()), key2.length());
    EXPECT_THROW_MSG(mode1.encrypt(input, output, inputLength), CryptoppApi::Exception, "key is not matching the one owned by the underlying cipher object");

    cipher.setKey(reinterpret_cast<const byte*>(key3.c_str()), key3.length());
    EXPECT_THROW_MSG(mode1.encrypt(input, output, inputLength), CryptoppApi::Exception, "key is not matching the one owned by the underlying cipher object");
}
