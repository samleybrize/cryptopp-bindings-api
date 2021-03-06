
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_MAC_HMAC_H
#define API_CRYPTOPP_MAC_HMAC_H

#include "src/api_cryptopp.h"
#include "src/hash/api_hash_interface.h"
#include "api_mac_abstract.h"
#include <hmac.h>

NAMESPACE_BEGIN(CryptoppApi)

// internal namespace
NAMESPACE_BEGIN(CryptoppApiInternal)

// Fork of the Crypto++ implementation of HMAC
// Allow to give a Hash object as a constructor argument
class CryptoppHmac : public CryptoPP::MessageAuthenticationCodeImpl<CryptoPP::HMAC_Base, CryptoppHmac>
{
public:
    CryptoppHmac(CryptoPP::HashTransformation *hash)
        : m_hash(hash) {}

    static std::string StaticAlgorithmName() {return std::string("HMAC");}
    std::string AlgorithmName() const {return std::string("HMAC(") + m_hash->AlgorithmName() + ")";}

private:
    CryptoPP::HashTransformation & AccessHash() {return *m_hash;}

    CryptoPP::HashTransformation *m_hash;
};

NAMESPACE_END // CryptoppApiInternal

// HMAC MAC algorithm implementation
class MacHmac : public MacAbstract
{
public:
    MacHmac(HashInterface *hash);
    ~MacHmac();

private:
    CryptoppApiInternal::CryptoppHmac *m_mac;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_MAC_HMAC_H */
