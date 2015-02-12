
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_mac_abstract.h"

NAMESPACE_BEGIN(CryptoppApi)

MacAbstract::MacAbstract()
    : m_mac(NULL)
    , m_name(NULL)
    , m_key(NULL)
    , m_keyLength(0)
{
}

MacAbstract::~MacAbstract()
{
    delete[] m_key;
}

const char *MacAbstract::getName() const
{
    return m_name;
}

void MacAbstract::setCryptoppObject(CryptoPP::MessageAuthenticationCode *mac)
{
    m_mac = mac;
}

bool MacAbstract::isValidKeyLength(size_t length) const
{
    return m_mac->IsValidKeyLength(length);
}

void MacAbstract::setKey(const byte *key, const size_t keyLength)
{
    // verify that the key is valid
    isValidKeyLength(keyLength, true);

    // free key
    if (NULL != m_key) {
        delete[] m_key;
    }

    // copy the key
    m_keyLength = keyLength;
    m_key       = new byte[keyLength];
    memcpy(m_key, key, keyLength);

    m_mac->SetKey(key, keyLength);
}

void MacAbstract::getKey(byte *key)
{
    memcpy(key, m_key, m_keyLength);
}

void MacAbstract::setName(const std::string name)
{
    m_name = const_cast<char*>(name.c_str());
}

const char *BlockCipherAbstract::getName() const
{
    return m_name;
}

size_t MacAbstract::getDigestSize() const
{
    return m_mac->DigestSize();
}

size_t MacAbstract::getBlockSize() const
{
    return m_mac->BlockSize();
}

void MacAbstract::calculateDigest(byte *input, size_t inputLength, byte *output)
{
    m_mac->CalculateDigest(output, input, inputLength);
}

void MacAbstract::update(byte *input, size_t inputLength)
{
    m_mac->Update(input, inputLength);
}

void MacAbstract::finalize(byte *output)
{
    m_mac->Final(output);
}

void MacAbstract::restart()
{
    m_mac->Restart();
}

NAMESPACE_END
