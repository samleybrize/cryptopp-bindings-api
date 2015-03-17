/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "src/symmetric/cipher/stream/api_stream_cipher_xsalsa20.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

TEST(StreamCipherXSalsa20Test, inheritance) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricCipherInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricTransformationInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::StreamCipherInterface*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::StreamCipherAbstract*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricKeyAbstract*>(&cipher));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::SymmetricIvAbstract*>(&cipher));
}

TEST(StreamCipherXSalsa20Test, infos) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    EXPECT_STREQ("xsalsa20", cipher.getName());
    EXPECT_EQ(1, cipher.getBlockSize());
}

TEST(StreamCipherXSalsa20Test, isValidKeyLength) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    EXPECT_FALSE(cipher.isValidKeyLength(16));
    EXPECT_TRUE(cipher.isValidKeyLength(32));
    EXPECT_FALSE(cipher.isValidKeyLength(9));
    EXPECT_FALSE(cipher.isValidKeyLength(0));
    EXPECT_FALSE(cipher.isValidKeyLength(33));
}

TEST(StreamCipherXSalsa20Test, isValidIvLength) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    EXPECT_TRUE(cipher.isValidIvLength(24));
    EXPECT_FALSE(cipher.isValidIvLength(16));
    EXPECT_FALSE(cipher.isValidIvLength(26));
}

TEST(StreamCipherXSalsa20Test, setGetKey) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    // build keys
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10", 64, &key, keyLength);

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

TEST(StreamCipherXSalsa20Test, setGetIv) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("010203040506070801020304050607080102030405060708", 48, &iv, ivLength);

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

TEST(StreamCipherXSalsa20Test, encrypt) {
    CryptoppApi::StreamCipherXSalsa20 cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2ecbb5a282ee515b3226952d11d0579607f653a708d18920d18dc5106f76074f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("53f67a3bada58382426b7d2142c327c7a9fa75a8634463c7", 48, &iv, ivLength);

    // build block
    byte *block;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("f097c0d167658edf4fbb3a9dd5ad2b71", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("39b420e15e86515fa935e6b32cf727c4", 32, &expected2, dummyLength);
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

TEST(StreamCipherXSalsa20Test, decrypt) {
    CryptoppApi::StreamCipherXSalsa20 cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *block1;
    byte *block2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2ecbb5a282ee515b3226952d11d0579607f653a708d18920d18dc5106f76074f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("53f67a3bada58382426b7d2142c327c7a9fa75a8634463c7", 48, &iv, ivLength);

    // build expected data
    byte *expected;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("f097c0d167658edf4fbb3a9dd5ad2b71", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("39b420e15e86515fa935e6b32cf727c4", 32, &block2, dummyLength);
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

TEST(StreamCipherXSalsa20Test, encrypt12Rounds) {
    CryptoppApi::StreamCipherXSalsa20 cipher(12);
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2ecbb5a282ee515b3226952d11d0579607f653a708d18920d18dc5106f76074f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("53f67a3bada58382426b7d2142c327c7a9fa75a8634463c7", 48, &iv, ivLength);

    // build block
    byte *block;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("4ceb42a120607593198ef1211eec957d", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("1a66979d67c996203e881a0b2e2120a7", 32, &expected2, dummyLength);
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

TEST(StreamCipherXSalsa20Test, decrypt12Rounds) {
    CryptoppApi::StreamCipherXSalsa20 cipher(12);
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *block1;
    byte *block2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2ecbb5a282ee515b3226952d11d0579607f653a708d18920d18dc5106f76074f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("53f67a3bada58382426b7d2142c327c7a9fa75a8634463c7", 48, &iv, ivLength);

    // build expected data
    byte *expected;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("4ceb42a120607593198ef1211eec957d", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("1a66979d67c996203e881a0b2e2120a7", 32, &block2, dummyLength);
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

TEST(StreamCipherXSalsa20Test, encrypt8Rounds) {
    CryptoppApi::StreamCipherXSalsa20 cipher(8);
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2ecbb5a282ee515b3226952d11d0579607f653a708d18920d18dc5106f76074f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("53f67a3bada58382426b7d2142c327c7a9fa75a8634463c7", 48, &iv, ivLength);

    // build block
    byte *block;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("50b85a918f837766062ad25b5a3bc542", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("4fcbd495ecfb35d22e2e7b3e301baf7f", 32, &expected2, dummyLength);
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

TEST(StreamCipherXSalsa20Test, decrypt8Rounds) {
    CryptoppApi::StreamCipherXSalsa20 cipher(8);
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *block1;
    byte *block2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2ecbb5a282ee515b3226952d11d0579607f653a708d18920d18dc5106f76074f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength = 0;
    CryptoppApi::HexUtils::hex2bin("53f67a3bada58382426b7d2142c327c7a9fa75a8634463c7", 48, &iv, ivLength);

    // build expected data
    byte *expected;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("50b85a918f837766062ad25b5a3bc542", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("4fcbd495ecfb35d22e2e7b3e301baf7f", 32, &block2, dummyLength);
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

TEST(StreamCipherXSalsa20Test, restartEncryption) {
    CryptoppApi::StreamCipherXSalsa20 cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2ecbb5a282ee515b3226952d11d0579607f653a708d18920d18dc5106f76074f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("53f67a3bada58382426b7d2142c327c7a9fa75a8634463c7", 48, &iv, ivLength);
    cipher.setIv(iv, ivLength);

    // build blocks
    byte *block;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &block, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("f097c0d167658edf4fbb3a9dd5ad2b71", 32, &expected, dummyLength);
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

TEST(StreamCipherXSalsa20Test, restartDecryption) {
    CryptoppApi::StreamCipherXSalsa20 cipher;
    size_t dataSize = 16;

    byte output1[dataSize];
    byte output2[dataSize];
    byte *expected1;
    byte *expected2;

    // build key
    byte *key;
    size_t keyLength = 0;
    CryptoppApi::HexUtils::hex2bin("2ecbb5a282ee515b3226952d11d0579607f653a708d18920d18dc5106f76074f", 64, &key, keyLength);

    // build iv
    byte *iv;
    size_t ivLength;
    CryptoppApi::HexUtils::hex2bin("53f67a3bada58382426b7d2142c327c7a9fa75a8634463c7", 48, &iv, ivLength);
    cipher.setIv(iv, ivLength);

    // build blocks
    byte *block1;
    byte *block2;
    size_t dummyLength = 0;
    CryptoppApi::HexUtils::hex2bin("f097c0d167658edf4fbb3a9dd5ad2b71", 32, &block1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("39b420e15e86515fa935e6b32cf727c4", 32, &block2, dummyLength);

    // calculate actual data
    CryptoppApi::HexUtils::hex2bin("00000000000000000000000000000000", 32, &expected1, dummyLength);
    CryptoppApi::HexUtils::hex2bin("c923e03039e3df80e68edc2ef95a0cb5", 32, &expected2, dummyLength);
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

TEST(StreamCipherXSalsa20Test, largeData) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    std::string key("12345678901234561234567890123456");
    std::string iv("123456781234567812345678");
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

TEST(StreamCipherXSalsa20Test, isStream) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    std::string key("12345678901234561234567890123456");
    std::string iv("123456781234567812345678");
    cipher.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());
    cipher.setIv(reinterpret_cast<const byte*>(iv.c_str()), iv.length());

    std::string dataStr("12345678901234567");
    const byte *data    = reinterpret_cast<const byte*>(dataStr.c_str());
    size_t dataLength   = dataStr.length();
    byte output[dataLength];

    cipher.encrypt(data, output, dataLength);
    cipher.decrypt(data, output, dataLength);
}

TEST(StreamCipherXSalsa20Test, invalidKey) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    byte key1[33];
    byte key2[0];
    memset(key1, 0, 33);

    EXPECT_THROW_MSG(cipher.setKey(key1, 33), CryptoppApi::Exception, "33 is not a valid key length");
    EXPECT_THROW_MSG(cipher.setKey(key2, 0), CryptoppApi::Exception, "a key is required");
}

TEST(StreamCipherXSalsa20Test, invalidIv) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    byte iv1[] = {45, 12, 14};
    byte iv2[0];

    EXPECT_THROW_MSG(cipher.setIv(iv1, 3), CryptoppApi::Exception, "3 is not a valid initialization vector length");
    EXPECT_THROW_MSG(cipher.setIv(iv2, 0), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(StreamCipherXSalsa20Test, cryptWithoutKey) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    size_t inputLength = cipher.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(cipher.encrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
    EXPECT_THROW_MSG(cipher.decrypt(input, output, inputLength), CryptoppApi::Exception, "a key is required");
}

TEST(StreamCipherXSalsa20Test, cryptWithoutIv) {
    CryptoppApi::StreamCipherXSalsa20 cipher;

    std::string key("12345678901234561234567890123456");
    cipher.setKey(reinterpret_cast<const byte*>(key.c_str()), key.length());

    size_t inputLength = cipher.getBlockSize();
    byte input[inputLength];
    byte output[inputLength];

    EXPECT_THROW_MSG(cipher.encrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
    EXPECT_THROW_MSG(cipher.decrypt(input, output, inputLength), CryptoppApi::Exception, "an initialization vector is required");
}

TEST(StreamCipherXSalsa20Test, invalidRoundNumber) {
    CryptoppApi::StreamCipherXSalsa20 cipher;
    EXPECT_THROW_MSG(cipher.setRounds(5), CryptoppApi::Exception, "number of rounds must be one of 8, 12 or 20");
}
