
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

class HashSha3_224 : public HashAbstract
{
public:
    HashSha3_224();
    size_t getBlockSize() const {return 72;}

private:
    CryptoPP::SHA3_224 m_hash;
};

class HashSha3_256 : public HashAbstract
{
public:
    HashSha3_256();
    size_t getBlockSize() const {return 104;}

private:
    CryptoPP::SHA3_256 m_hash;
};

class HashSha3_384 : public HashAbstract
{
public:
    HashSha3_384();
    size_t getBlockSize() const {return 136;}

private:
    CryptoPP::SHA3_384 m_hash;
};

class HashSha3_512 : public HashAbstract
{
public:
    HashSha3_512();
    size_t getBlockSize() const {return 144;}

private:
    CryptoPP::SHA3_512 m_hash;
};

NAMESPACE_END

#else /* CRYPTOPP_VERSION */

#define CRYPTOPP_SHA3_ENABLED 0

#endif /* CRYPTOPP_VERSION */

#endif /* API_CRYPTOPP_HASH_SHA3_H */
