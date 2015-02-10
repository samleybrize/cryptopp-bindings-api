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
            throw new Exception("an initialization vector is required");
        } else {
            throw new Exception(length << " is not a valid initialization vector length");
        }
    }

    return isValid;
}

NAMESPACE_END
