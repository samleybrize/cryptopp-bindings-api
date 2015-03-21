
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_mac_cmac.h"
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

bool CryptoppCmac::IsValidKeyLength(size_t n) const
{
    return m_cipher->IsValidKeyLength(n);
}

void CryptoppCmac::UncheckedSetKey(const byte *key, unsigned int keylength, const CryptoPP::NameValuePairs &params)
{
    CryptoPP::CMAC_Base::UncheckedSetKey(key, keylength, params);

    // update cipher key
    m_cipher->SetKey(key, keylength);
}

MacCmac::MacCmac(BlockCipherAbstract *cipher)
    : MacAbstract()
    , m_cipher(cipher)
{
    // name
    std::string name("cmac(");
    name.append(cipher->getName());
    name.append(")");
    setName(name);

    // create mac object
    m_mac = new CryptoppCmac(cipher->getEncryptor());
    setCryptoppObject(m_mac);
}

MacCmac::~MacCmac()
{
    delete m_mac;
}

void MacCmac::setKey(const byte *key, const size_t keyLength)
{
    MacAbstract::setKey(key, keyLength);
    m_cipher->setKey(key, keyLength);
}

void MacCmac::calculateDigest(const byte *input, size_t inputLength, byte *output)
{
    hasValidKey(true);

    // verify that key is equals to underlying cipher key
    if (!isKeyEqualsTo(m_cipher)) {
        throw Exception("key is not matching the one owned by the underlying cipher object");
    }

    MacAbstract::calculateDigest(input, inputLength, output);
}

void MacCmac::update(const byte *input, size_t inputLength)
{
    hasValidKey(true);

    // verify that key is equals to underlying cipher key
    if (!isKeyEqualsTo(m_cipher)) {
        throw Exception("key is not matching the one owned by the underlying cipher object");
    }

    MacAbstract::update(input, inputLength);
}

void MacCmac::finalize(byte *output)
{
    hasValidKey(true);

    // verify that key is equals to underlying cipher key
    if (!isKeyEqualsTo(m_cipher)) {
        throw Exception("key is not matching the one owned by the underlying cipher object");
    }

    MacAbstract::finalize(output);
}

NAMESPACE_END
