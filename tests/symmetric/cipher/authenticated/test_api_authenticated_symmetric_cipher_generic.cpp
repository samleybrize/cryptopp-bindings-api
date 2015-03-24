/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/hash/api_hash_sha1.h"
#include "src/mac/api_mac_hmac.h"
#include "src/symmetric/cipher/authenticated/api_authenticated_symmetric_cipher_generic.h"
#include "src/symmetric/cipher/stream/api_stream_cipher_sosemanuk.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(AuthenticatedSymmetricCipherGenericTest, inheritance) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricCipherInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricTransformationInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::AuthenticatedSymmetricCipherInterface*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::AuthenticatedSymmetricCipherAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&mode));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricIvAbstract*>(&mode));
}

TEST(AuthenticatedSymmetricCipherGenericTest, infos) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    EXPECT_STREQ("sosemanuk/hmac(sha1)", mode.getName());
    EXPECT_EQ(1, mode.getBlockSize());
    EXPECT_EQ(20, mode.getDigestSize());
}

TEST(AuthenticatedSymmetricCipherGenericTest, isValidKeyLength) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    EXPECT_TRUE(mode.isValidKeyLength(16));
    EXPECT_FALSE(mode.isValidKeyLength(0));
    EXPECT_FALSE(mode.isValidKeyLength(33));
}

TEST(AuthenticatedSymmetricCipherGenericTest, isValidIvLength) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    EXPECT_TRUE(mode.isValidIvLength(16));
    EXPECT_FALSE(mode.isValidIvLength(2));
    EXPECT_FALSE(mode.isValidIvLength(20));
}

TEST(AuthenticatedSymmetricCipherGenericTest, isValidMacKeyLength) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    EXPECT_TRUE(mode.isValidMacKeyLength(16));
    EXPECT_TRUE(mode.isValidMacKeyLength(5));
    EXPECT_TRUE(mode.isValidMacKeyLength(65));
}

TEST(AuthenticatedSymmetricCipherGenericTest, setGetKey) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("010203040506", 12, &key, keyLength);

    // set/get keys
    size_t key0Length = mode.getKeyLength();

    mode.setKey(key, keyLength);
    size_t keyGetLength = mode.getKeyLength();
    byte keyGet[keyGetLength];
    mode.getKey(keyGet);

    // test keys
    EXPECT_EQ(0, key0Length);
    EXPECT_BYTE_ARRAY_EQ(key, keyLength, keyGet, keyGetLength);

    delete[] key;
}

TEST(AuthenticatedSymmetricCipherGenericTest, setGetMacKey) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("010203040506070809", 12, &key, keyLength);

    // set/get keys
    size_t key0Length = mode.getMacKeyLength();

    mode.setMacKey(key, keyLength);
    size_t keyGetLength = mode.getMacKeyLength();
    byte keyGet[keyGetLength];
    mode.getMacKey(keyGet);

    // test keys
    EXPECT_EQ(0, key0Length);
    EXPECT_BYTE_ARRAY_EQ(key, keyLength, keyGet, keyGetLength);

    delete[] key;
}

TEST(AuthenticatedSymmetricCipherGenericTest, setGetIv) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

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

TEST(AuthenticatedSymmetricCipherGenericTest, encrypt) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);
    size_t dataSize     = 16;
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
    CryptoppApi::HexUtils::hex2bin("a7c083feb7", 10, &key, keyLength);

    // build mac key
    byte *macKey;
    size_t macKeyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &macKey, macKeyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block2, dummyLength);

    // sosemanuk
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("be6a431a935cb90e2221ebb7ef502328", 32, &expected2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("15cbfe20bb447711c2700b5eddada57323007973", 40, &expected3, dummyLength);
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
    delete[] macKey;
    delete[] block1;
    delete[] block2;
}

TEST(AuthenticatedSymmetricCipherGenericTest, decrypt) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);
    size_t dataSize     = 16;
    size_t digestSize   = mode.getDigestSize();

    byte output1[dataSize];
    byte output2[dataSize];
    byte output3[digestSize];
    byte *block1;
    byte *block2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("a7c083feb7", 10, &key, keyLength);

    // build mac key
    byte *macKey;
    size_t macKeyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &macKey, macKeyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build expected data
    byte *expected1;
    byte *expected2;
    byte *expected3;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("15cbfe20bb447711c2700b5eddada57323007973", 40, &expected3, dummyLength);

    // sosemanuk
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("be6a431a935cb90e2221ebb7ef502328", 32, &block2, dummyLength);
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
    delete[] macKey;
    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
}

TEST(AuthenticatedSymmetricCipherGenericTest, restartEncryption) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);
    size_t dataSize     = 16;
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
    CryptoppApi::HexUtils::hex2bin("a7c083feb7", 10, &key, keyLength);

    // build mac key
    byte *macKey;
    size_t macKeyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &macKey, macKeyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &expected2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("9fc9456bb645743c404a85619a2f0f6fe754791b", 40, &expected3, dummyLength);
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
    delete[] macKey;
    delete[] iv;
    delete[] block1;
    delete[] block2;
}

TEST(AuthenticatedSymmetricCipherGenericTest, restartDecryption) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);
    size_t dataSize     = 16;
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
    CryptoppApi::HexUtils::hex2bin("a7c083feb7", 10, &key, keyLength);

    // build mac key
    byte *macKey;
    size_t macKeyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &macKey, macKeyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("be6a431a935cb90e2221ebb7ef502328", 32, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("40eb910cbfc6a90326a8b7f2a5277273", 32, &expected2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("f044210a699da578851f2a700205218fc03a6e9d", 40, &expected3, dummyLength);
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
    delete[] macKey;
    delete[] iv;
    delete[] block1;
    delete[] block2;
}

TEST(AuthenticatedSymmetricCipherGenericTest, encryptWithAad) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);
    size_t dataSize     = 16;
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
    CryptoppApi::HexUtils::hex2bin("a7c083feb7", 10, &key, keyLength);

    // build mac key
    byte *macKey;
    size_t macKeyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &macKey, macKeyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    byte *aad;
    size_t dummyLength  = 0;
    size_t block1Length = 0;
    size_t block2Length = 0;
    size_t aadLength    = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block1, block1Length);
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block2, block2Length);
    CryptoppApi::HexUtils::hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", 40, &aad, aadLength);

    // sosemanuk
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("be6a431a935cb90e2221ebb7ef502328", 32, &expected2, dummyLength);
    CryptoppApi::HexUtils::hex2bin("ccc6f4a1ccb0c3e03a0b3e103613bef65d5f61de", 40, &expected3, dummyLength);
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
    delete[] macKey;
    delete[] block1;
    delete[] block2;
    delete[] aad;
}

TEST(AuthenticatedSymmetricCipherGenericTest, decryptWithAad) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);
    size_t dataSize     = 16;
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
    CryptoppApi::HexUtils::hex2bin("a7c083feb7", 10, &key, keyLength);

    // build mac key
    byte *macKey;
    size_t macKeyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &macKey, macKeyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("00112233445566778899aabbccddeeff", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build expected data
    byte *expected1;
    byte *expected2;
    byte *expected3;
    size_t dummyLength      = 0;
    size_t expected1Length  = 0;
    size_t expected2Length  = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected1, expected1Length);
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected2, expected2Length);
    CryptoppApi::HexUtils::hex2bin("ccc6f4a1ccb0c3e03a0b3e103613bef65d5f61de", 40, &expected3, dummyLength);

    // sosemanuk
    size_t aadLength = 0;
    CryptoppApi::HexUtils::hex2bin("fe81d2162c9a100d04895c454a77515b", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("be6a431a935cb90e2221ebb7ef502328", 32, &block2, dummyLength);
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
    delete[] macKey;
    delete[] expected1;
    delete[] expected2;
    delete[] expected3;
}

TEST(AuthenticatedSymmetricCipherGenericTest, encryptAadOnly) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);
    size_t digestSize = mode.getDigestSize();

    byte output[digestSize];
    byte *expected;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("77be637089", 10, &key, keyLength);

    // build mac key
    byte *macKey;
    size_t macKeyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &macKey, macKeyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("e0e00f19fed7ba0136a797f3ed7ba013", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build aad
    byte *aad;
    size_t aadLength = 0;
    CryptoppApi::HexUtils::hex2bin("7a43ec1d9c0a5a78a0b16533a6213cab", 32, &aad, aadLength);

    // sosemanuk
    CryptoppApi::HexUtils::hex2bin("02a2913e1a34d07005ebf2ba59a1008ba1f1307f", 40, &expected, digestSize);
    mode.setKey(key, keyLength);
    mode.addEncryptionAdditionalData(aad, aadLength);
    mode.finalizeEncryption(output);
    EXPECT_BYTE_ARRAY_EQ(expected, digestSize, output, digestSize);

    delete[] expected;
    delete[] iv;
    delete[] key;
    delete[] macKey;
    delete[] aad;
}

TEST(AuthenticatedSymmetricCipherGenericTest, decryptAadOnly) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);
    size_t digestSize = mode.getDigestSize();

    byte output[digestSize];
    byte *expected;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("77be637089", 10, &key, keyLength);

    // build mac key
    byte *macKey;
    size_t macKeyLength = 0;
    CryptoppApi::HexUtils::hex2bin("feffe9928665731c6d6a8f9467308308", 32, &macKey, macKeyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("e0e00f19fed7ba0136a797f3ed7ba013", 32, &iv, ivLength);
    mode.setIv(iv, ivLength);

    // build aad
    byte *aad;
    size_t aadLength = 0;
    CryptoppApi::HexUtils::hex2bin("7a43ec1d9c0a5a78a0b16533a6213cab", 32, &aad, aadLength);

    // sosemanuk
    CryptoppApi::HexUtils::hex2bin("02a2913e1a34d07005ebf2ba59a1008ba1f1307f", 40, &expected, digestSize);
    mode.setKey(key, keyLength);
    mode.addDecryptionAdditionalData(aad, aadLength);
    mode.finalizeDecryption(output);
    EXPECT_BYTE_ARRAY_EQ(expected, digestSize, output, digestSize);

    delete[] expected;
    delete[] iv;
    delete[] key;
    delete[] macKey;
    delete[] aad;
}

TEST(AuthenticatedSymmetricCipherGenericTest, largeData) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    std::string key("1234567890123456");
    std::string macKey("1234567890123456");
    std::string iv("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    mode.setMacKey(reinterpret_cast<const byte*>(macKey.c_str()), macKey.length());
    mode.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    size_t dataSize = 10485760;
    byte *input     = new byte[dataSize];
    byte *output    = new byte[dataSize];
    memset(input, 125, dataSize);
    mode.addEncryptionAdditionalData(input, dataSize);
    mode.addDecryptionAdditionalData(input, dataSize);
    mode.encrypt(input, output, dataSize);
    mode.decrypt(input, output, dataSize);

    delete[] input;
    delete[] output;
}

// TODO
TEST(AuthenticatedSymmetricCipherGenericTest, isStream) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

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

TEST(AuthenticatedSymmetricCipherGenericTest, invalidKey) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    byte key1[33];
    byte key2[0];

    EXPECT_THROW_MSG(mode.setKey(key1, 33), CryptoppApi::Exception, "33 is not a valid key length");
    EXPECT_THROW_MSG(mode.setKey(key2, 0), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherGenericTest, invalidIv) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    byte iv1[0];
    byte iv2[3];
    EXPECT_THROW_MSG(mode.setIv(iv1, 0), CryptoppApi::Exception, "an initialization vector is required");
    EXPECT_THROW_MSG(mode.setIv(iv2, 3), CryptoppApi::Exception, "3 is not a valid initialization vector length");
}

TEST(AuthenticatedSymmetricCipherGenericTest, cryptWithoutKey) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherGenericTest, cryptWithoutIv) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    std::string key("1234567890123456");
    mode.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    size_t inputLength = mode.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(mode.encrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
    EXPECT_THROW_MSG(mode.decrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
}

// TODO cryptWithoutMacKey

TEST(AuthenticatedSymmetricCipherGenericTest, cryptAadWithoutKey) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    byte input[10];

    EXPECT_THROW_MSG(mode.addEncryptionAdditionalData(input, 10), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.addDecryptionAdditionalData(input, 10), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherGenericTest, finalizeWithoutKey) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

    byte output[mode.getDigestSize()];

    EXPECT_THROW_MSG(mode.finalizeEncryption(output), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(mode.finalizeDecryption(output), CryptoppApi::Exception, "a key is required");
}

TEST(AuthenticatedSymmetricCipherGenericTest, cryptBeforeAad) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode(&cipher, &mac);

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

// TODO
TEST(AuthenticatedSymmetricCipherGenericTest, keyNotMatchingUnderlyingOne) {
    CryptoppApi::StreamCipherSosemanuk cipher;
    CryptoppApi::HashSha1 hash;
    CryptoppApi::MacHmac mac(&hash);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode1(&cipher, &mac);
    CryptoppApi::AuthenticatedSymmetricCipherGeneric mode2(&cipher, &mac);

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
