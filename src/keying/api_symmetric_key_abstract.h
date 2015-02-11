
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_SYMMETRIC_KEY_ABSTRACT_H
#define API_CRYPTOPP_SYMMETRIC_KEY_ABSTRACT_H

#include "src/api_cryptopp.h"

NAMESPACE_BEGIN(CryptoppApi)

class SymmetricKeyAbstract
{
public:
    virtual ~SymmetricKeyAbstract() {}

    virtual bool isValidKeyLength(size_t length) const =0;
    bool isValidKeyLength(size_t length, bool throwIfFalse) const;
    virtual void setKey(const byte *key, const size_t keyLength) =0;
    virtual void getKey(byte *key) =0;
    virtual size_t getKeyLength() =0;

protected:
    bool hasValidKey(bool throwIfFalse);
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_KEY_ABSTRACT_H */
