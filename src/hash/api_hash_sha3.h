
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_HASH_SHA3_H
#define API_CRYPTOPP_HASH_SHA3_H

#include "src/api_cryptopp.h"

#if CRYPTOPP_VERSION >= 562

#define CRYPTOPP_SHA3_ENABLED 1

#include "api_hash_abstract.h"
#include <sha3.h>

NAMESPACE_BEGIN(CryptoppApi)

// internal namespace
NAMESPACE_BEGIN(CryptoppApiInternal)

// Fork of the Crypto++ implementation of Sha3-224
// Adds the block size used by the HMAC algorithm
class CryptoppSha3_224 : public CryptoPP::SHA3_224
{
public:
    unsigned int BlockSize() const {return 72;}
};

// Fork of the Crypto++ implementation of Sha3-256
// Adds the block size used by the HMAC algorithm
class CryptoppSha3_256 : public CryptoPP::SHA3_256
{
public:
    unsigned int BlockSize() const {return 104;}
};

// Fork of the Crypto++ implementation of Sha3-384
// Adds the block size used by the HMAC algorithm
class CryptoppSha3_384 : public CryptoPP::SHA3_384
{
public:
    unsigned int BlockSize() const {return 136;}
};

// Fork of the Crypto++ implementation of Sha3-512
// Adds the block size used by the HMAC algorithm
class CryptoppSha3_512 : public CryptoPP::SHA3_512
{
public:
    unsigned int BlockSize() const {return 144;}
};

NAMESPACE_END // CryptoppApiInternal

// Sha3-224 hash function implementation
class HashSha3_224 : public HashAbstract
{
public:
    HashSha3_224();

private:
    CryptoppApiInternal::CryptoppSha3_224 m_hash;
};

// Sha3-256 hash function implementation
class HashSha3_256 : public HashAbstract
{
public:
    HashSha3_256();

private:
    CryptoppApiInternal::CryptoppSha3_256 m_hash;
};

// Sha3-384 hash function implementation
class HashSha3_384 : public HashAbstract
{
public:
    HashSha3_384();

private:
    CryptoppApiInternal::CryptoppSha3_384 m_hash;
};

// Sha3-512 hash function implementation
class HashSha3_512 : public HashAbstract
{
public:
    HashSha3_512();

private:
    CryptoppApiInternal::CryptoppSha3_512 m_hash;
};

NAMESPACE_END

#else /* CRYPTOPP_VERSION */

#define CRYPTOPP_SHA3_ENABLED 0

#endif /* CRYPTOPP_VERSION */

#endif /* API_CRYPTOPP_HASH_SHA3_H */
