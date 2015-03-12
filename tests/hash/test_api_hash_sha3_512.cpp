/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/hash/api_hash_sha3.h"
#include "src/mac/api_mac_hmac.h"
#include "src/utils/api_hex_utils.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

#if CRYPTOPP_SHA3_ENABLED == 1

TEST(HashSha3_512Test, inheritance) {
    CryptoppApi::HashSha3_512 hash;

    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashTransformationInterface*>(&hash));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashInterface*>(&hash));
    EXPECT_TRUE(0 != dynamic_cast<CryptoppApi::HashAbstract*>(&hash));
}

TEST(HashSha3_512Test, infos) {
    CryptoppApi::HashSha3_512 hash;

    EXPECT_STREQ("sha3_512", hash.getName());
    EXPECT_EQ(144, hash.getBlockSize());
    EXPECT_EQ(64, hash.getDigestSize());
}

TEST(HashSha3_512Test, calculateDigest) {
    CryptoppApi::HashSha3_512 hash;

    // build expected digests
    byte *expected1;
    byte *expected2;
    size_t expected1Length = 0;
    size_t expected2Length = 0;
    CryptoppApi::HexUtils::hex2bin("a11d37ec4d9a4d6030e01faafdf75c4ba7537968e1debd5163fa57f44a847bbc96c8b193b2eb2dc29fac7c661976ede60728e4d794c12e97dac6869063ce252f", 128, &expected1, expected1Length);
    CryptoppApi::HexUtils::hex2bin("f2cf847e80859f5a67a726eb3fb333ae882fc1f2f8bfaa5fdb939c9143bc4849a229bf435e95e57f23aea2e1845c263e4288673a18f4d1123c92da6b954904b3", 128, &expected2, expected2Length);

    // calculate actual digests
    const char *input1  = "qwertyuiop";
    const char *input2  = "azerty";
    size_t digestSize   = hash.getDigestSize();
    byte actual1[digestSize];
    byte actual2[digestSize];

    hash.calculateDigest(reinterpret_cast<const byte*>(input1), strlen(input1), actual1);
    hash.calculateDigest(reinterpret_cast<const byte*>(input2), strlen(input2), actual2);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected1, expected1Length, actual1, digestSize);
    EXPECT_BYTE_ARRAY_EQ(expected2, expected2Length, actual2, digestSize);

    delete[] expected1;
    delete[] expected2;
}

TEST(HashSha3_512Test, update) {
    CryptoppApi::HashSha3_512 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("a11d37ec4d9a4d6030e01faafdf75c4ba7537968e1debd5163fa57f44a847bbc96c8b193b2eb2dc29fac7c661976ede60728e4d794c12e97dac6869063ce252f", 128, &expected, expectedLength);

    // calculate actual digest
    const char *input1  = "qwerty";
    const char *input2  = "uio";
    const char *input3  = "p";
    size_t digestSize   = hash.getDigestSize();
    byte actual[digestSize];

    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<const byte*>(input2), strlen(input2));
    hash.update(reinterpret_cast<const byte*>(input3), strlen(input3));

    hash.finalize(actual);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(HashSha3_512Test, restartNotNecessaryAfterFinalize) {
    CryptoppApi::HashSha3_512 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("a11d37ec4d9a4d6030e01faafdf75c4ba7537968e1debd5163fa57f44a847bbc96c8b193b2eb2dc29fac7c661976ede60728e4d794c12e97dac6869063ce252f", 128, &expected, expectedLength);

    // calculate actual digest
    const char *input1  = "qwerty";
    const char *input2  = "uio";
    const char *input3  = "p";
    size_t digestSize   = hash.getDigestSize();
    byte actual[digestSize];

    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.finalize(actual);

    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<const byte*>(input2), strlen(input2));
    hash.update(reinterpret_cast<const byte*>(input3), strlen(input3));

    hash.finalize(actual);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(HashSha3_512Test, restart) {
    CryptoppApi::HashSha3_512 hash;

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("a11d37ec4d9a4d6030e01faafdf75c4ba7537968e1debd5163fa57f44a847bbc96c8b193b2eb2dc29fac7c661976ede60728e4d794c12e97dac6869063ce252f", 128, &expected, expectedLength);

    // calculate actual digest
    const char *input1  = "qwerty";
    const char *input2  = "uio";
    const char *input3  = "p";
    size_t digestSize   = hash.getDigestSize();
    byte actual[digestSize];

    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.restart();

    hash.update(reinterpret_cast<const byte*>(input1), strlen(input1));
    hash.update(reinterpret_cast<const byte*>(input2), strlen(input2));
    hash.update(reinterpret_cast<const byte*>(input3), strlen(input3));

    hash.finalize(actual);

    // test digests
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, digestSize);

    delete[] expected;
}

TEST(HashSha3_512Test, largeData) {
    CryptoppApi::HashSha3_512 hash;

    size_t digestSize   = hash.getDigestSize();
    byte *input         = new byte[10485760];
    byte output[digestSize];

    hash.calculateDigest(input, 10485760, output);
    hash.update(input, 10485760);
    hash.finalize(output);

    delete[] input;
}

TEST(HashSha3_512Test, hmac) {
    CryptoppApi::HashSha3_512 hash;
    CryptoppApi::MacHmac mac(&hash);

    // build expected digest
    byte *expected;
    size_t expectedLength = 0;
    CryptoppApi::HexUtils::hex2bin("13c2b0598bf7bed1272463925ca0c9ce35839c5276cf08342b093e98a0d5c0af9c7606e3d81bf59f410729832ffb83d728eb50e9a45229ae3c41ce8bb4314a63", 128, &expected, expectedLength);

    // calculate digest
    std::string inputStr("Hi There");
    const byte *input   = reinterpret_cast<const byte*>(inputStr.c_str());
    size_t inputLength  = inputStr.length();

    byte *key;
    size_t keyLength    = 0;
    CryptoppApi::HexUtils::hex2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 32, &key, keyLength);
    mac.setKey(key, keyLength);

    byte actual[mac.getDigestSize()];
    mac.calculateDigest(input, inputLength, actual);
    EXPECT_BYTE_ARRAY_EQ(expected, expectedLength, actual, mac.getDigestSize());

    delete[] expected;
    delete[] key;
}

#endif /* CRYPTOPP_SHA3_ENABLED == 1 */
