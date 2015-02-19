/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/hash/api_hash_md5.h"
#include "tests/test_api_assertions.h"
#include <gtest/gtest.h>

// TODO is instanceof HashInterface
// TODO is instanceof HashAbstract

TEST(HashMd5Test, infos) {
    CryptoppApi::HashMd5 hash;

    EXPECT_STREQ("md5", hash.getName());
    EXPECT_EQ(64, hash.getBlockSize());
    EXPECT_EQ(16, hash.getDigestSize());
}

// TODO calculateDigest
// TODO update
// TODO finalize
// TODO restart
