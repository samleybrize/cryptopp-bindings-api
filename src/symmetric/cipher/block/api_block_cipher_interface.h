
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_BLOCK_CIPHER_INTERFACE_H
#define API_CRYPTOPP_BLOCK_CIPHER_INTERFACE_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/api_symmetric_cipher_interface.h"

NAMESPACE_BEGIN(CryptoppApi)

class BlockCipherInterface : public SymmetricCipherInterface
{
public:
    virtual ~BlockCipherInterface() {}

    virtual void encrypt(const byte *input, byte *output, const size_t length) =0;
    virtual void decrypt(const byte *input, byte *output, const size_t length) =0;
    virtual void encryptBlock(const byte *input, byte *output, const size_t length) =0;
    virtual void decryptBlock(const byte *input, byte *output, const size_t length) =0;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_BLOCK_CIPHER_INTERFACE_H */
