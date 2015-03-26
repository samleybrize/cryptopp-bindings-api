
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_MAC_CMAC_H
#define API_CRYPTOPP_MAC_CMAC_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/block/api_block_cipher_abstract.h"
#include "api_mac_abstract.h"
#include <cmac.h>

NAMESPACE_BEGIN(CryptoppApi)

// internal namespace
NAMESPACE_BEGIN(CryptoppApiInternal)

// Fork of the Crypto++ implementation of CMAC
// Allow to give a cipher as a constructor argument
class CryptoppCmac : public CryptoPP::CMAC_Base
{
public:
    CryptoppCmac(CryptoPP::BlockCipher *cipher)
        : m_cipher(cipher) {}

    bool IsValidKeyLength(size_t n) const;
    void UncheckedSetKey(const byte *key, unsigned int keylength, const CryptoPP::NameValuePairs &params);

    size_t MinKeyLength() const {return m_cipher->MinKeyLength();}
    size_t MaxKeyLength() const {return m_cipher->MaxKeyLength();}
    size_t DefaultKeyLength() const {return m_cipher->DefaultKeyLength();}
    size_t GetValidKeyLength(size_t n) const {return m_cipher->GetValidKeyLength(n);}
    SimpleKeyingInterface::IV_Requirement IVRequirement() const {return m_cipher->IVRequirement();}
    unsigned int IVSize() const {return m_cipher->IVSize();}

    static std::string StaticAlgorithmName() {return std::string("CMAC");}
    std::string AlgorithmName() const {return std::string("CMAC(") + m_cipher->AlgorithmName() + ")";}

private:
    CryptoPP::BlockCipher & AccessCipher() {return *m_cipher;}

    CryptoPP::BlockCipher *m_cipher;
};

NAMESPACE_END // CryptoppApiInternal

// CMAC MAC algorithm implementation
class MacCmac : public MacAbstract
{
public:
    // TODO comment
    MacCmac(BlockCipherAbstract *cipher);
    ~MacCmac();

    void setKey(const byte *key, const size_t keyLength);
    void calculateDigest(const byte *input, size_t inputLength, byte *output);
    void update(const byte *input, size_t inputLength);
    void finalize(byte *output);

private:
    // TODO comment
    CryptoppApiInternal::CryptoppCmac *m_mac;
    BlockCipherAbstract *m_cipher;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_MAC_CMAC_H */
