
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_SYMMETRIC_IV_ABSTRACT_H
#define API_CRYPTOPP_SYMMETRIC_IV_ABSTRACT_H

#include "src/api_cryptopp.h"

NAMESPACE_BEGIN(CryptoppApi)

class SymmetricIvAbstract
{
public:
    virtual ~SymmetricIvAbstract() {}

    virtual bool isValidIvLength(size_t length) const =0;
    bool isValidIvLength(size_t length, bool throwIfFalse) const;
    virtual void setIv(const byte *iv, const size_t ivLength) =0;
    virtual void getIv(byte *iv) =0;
    virtual size_t getIvLength() =0;

protected:
    bool hasValidIv(bool throwIfFalse);
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_IV_ABSTRACT_H */
