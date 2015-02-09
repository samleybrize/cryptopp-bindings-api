
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_SYMMETRIC_CIPHER_INTERFACE_H
#define API_CRYPTOPP_SYMMETRIC_CIPHER_INTERFACE_H

#include "src/api_cryptopp.h"

NAMESPACE_BEGIN(CryptoppApi)

class SymmetricCipherInterface
{
public:
    virtual ~SymmetricCipherInterface() {}

    virtual const char *getName() const =0;
    virtual size_t getBlockSize() const =0;
    virtual bool isValidKeyLength(size_t length) const =0;
    virtual void setKey(const byte *key, const size_t keyLength) =0;
    virtual void getKey(byte **key, size_t &length) =0;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_CIPHER_INTERFACE_H */
