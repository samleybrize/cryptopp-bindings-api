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

NAMESPACE_BEGIN(CryptoppApi)

bool SymmetricKeyAbstract::hasValidKey(bool throwIfFalse)
{
    return isValidKeyLength(getKeyLength(), true);
}

bool SymmetricKeyAbstract::isValidKeyLength(size_t length, bool throwIfFalse) const
{
    bool isValid = isValidKeyLength(length);

    if (!isValid && throwIfFalse) {
        if (0 == length) {
            throw new Exception("a key is required");
        } else {
            throw new Exception(length << " is not a valid key length");
        }
    }

    return isValid;
}

NAMESPACE_END
