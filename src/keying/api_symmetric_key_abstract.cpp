/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_symmetric_key_abstract.h"
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

bool SymmetricKeyAbstract::hasValidKey(bool throwIfFalse)
{
    return isValidKeyLength(getKeyLength(), throwIfFalse);
}

bool SymmetricKeyAbstract::isValidKeyLength(size_t length, bool throwIfFalse) const
{
    bool isValid = isValidKeyLength(length);

    if (!isValid && throwIfFalse) {
        if (0 == length) {
            throw Exception("a key is required");
        } else {
            std::stringstream msg;
            msg << length << " is not a valid key length";
            throw Exception(msg.str());
        }
    }

    return isValid;
}

void SymmetricKeyAbstract::getKey(byte *key)
{
    memcpy(key, m_key, m_keyLength);
}

void SymmetricKeyAbstract::setKey(const byte *key, const size_t keyLength)
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
}

bool SymmetricKeyAbstract::isKeyEqualsTo(SymmetricKeyAbstract *compare)
{
    // compare keys lengths
    size_t keyLength        = getKeyLength();
    size_t compareKeyLength = compare->getKeyLength();

    if (keyLength != compareKeyLength) {
        return false;
    }

    // compare keys
    byte compareKey[compareKeyLength];
    compare->getKey(compareKey);

    for (int i = 0; i < keyLength; i++) {
        if (m_key[i] != compareKey[i]) {
            return false;
        }
    }

    return true;
}

NAMESPACE_END
