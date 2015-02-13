
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_HASH_MD5_H
#define API_CRYPTOPP_HASH_MD5_H

#include "src/api_cryptopp.h"
#include "api_hash_abstract.h"
#include <md5.h>

NAMESPACE_BEGIN(CryptoppApi)

class HashMd5 : public HashAbstract
{
public:
    HashMd5();

private:
    CryptoPP::Weak::MD5 m_hash;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_HASH_MD5_H */
