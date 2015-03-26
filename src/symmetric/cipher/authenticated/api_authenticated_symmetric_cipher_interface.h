
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_INTERFACE_H
#define API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_INTERFACE_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/api_symmetric_transformation_interface.h"

NAMESPACE_BEGIN(CryptoppApi)

// TODO comments
class AuthenticatedSymmetricCipherInterface : public SymmetricTransformationInterface
{
public:
    virtual ~AuthenticatedSymmetricCipherInterface() {}

    virtual size_t getDigestSize() const =0;
    virtual void addEncryptionAdditionalData(const byte *data, size_t dataLength) =0;
    virtual void addDecryptionAdditionalData(const byte *data, size_t dataLength) =0;
    virtual void finalizeEncryption(byte *output) =0;
    virtual void finalizeDecryption(byte *output) =0;

    virtual CryptoPP::AuthenticatedSymmetricCipher *getEncryptor() =0;
    virtual CryptoPP::AuthenticatedSymmetricCipher *getDecryptor() =0;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_INTERFACE_H */
