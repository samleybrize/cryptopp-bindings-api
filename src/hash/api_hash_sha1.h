
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_HASH_SHA1_H
#define API_CRYPTOPP_HASH_SHA1_H

#include "src/api_cryptopp.h"
#include "api_hash_abstract.h"
#include <sha.h>

NAMESPACE_BEGIN(CryptoppApi)

// Sha1 hash function implementation
class HashSha1 : public HashAbstract
{
public:
    HashSha1();

private:
    CryptoPP::SHA1 m_hash;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_HASH_SHA1_H */
