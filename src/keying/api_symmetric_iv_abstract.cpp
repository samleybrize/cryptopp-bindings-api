/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_symmetric_iv_abstract.h"
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

bool SymmetricIvAbstract::hasValidIv(bool throwIfFalse)
{
    return isValidIvLength(getIvLength(), true);
}

bool SymmetricIvAbstract::isValidIvLength(size_t length, bool throwIfFalse) const
{
    bool isValid = isValidIvLength(length);

    if (!isValid && throwIfFalse) {
        if (0 == length) {
            throw Exception("an initialization vector is required");
        } else {
            std::stringstream msg;
            msg << length << " is not a valid initialization vector length";
            throw Exception(msg.str());
        }
    }

    return isValid;
}

void SymmetricIvAbstract::getIv(byte *iv)
{
    memcpy(iv, m_iv, m_ivLength);
}

void SymmetricIvAbstract::setIv(const byte *iv, const size_t ivLength)
{
    // verify that the iv is valid
    isValidIvLength(ivLength, true);

    // free iv
    if (NULL != m_iv) {
        delete[] m_iv;
    }

    // copy the iv
    m_ivLength  = ivLength;
    m_iv        = new byte[ivLength];
    memcpy(m_iv, iv, ivLength);
}

NAMESPACE_END
