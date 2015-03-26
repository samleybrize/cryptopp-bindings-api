
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
#include "src/keying/api_symmetric_key_abstract.h"

NAMESPACE_BEGIN(CryptoppApi)

// Interface for symmetric cipher implementations that require a key
class SymmetricCipherInterface : public SymmetricKeyAbstract
{
public:
    // TODO comments
    virtual ~SymmetricCipherInterface() {}

    virtual const char *getName() const =0;
    virtual size_t getBlockSize() const =0;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_CIPHER_INTERFACE_H */
