
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

// Interface for block cipher implementations
class BlockCipherInterface : public SymmetricCipherInterface
{
public:
    virtual ~BlockCipherInterface() {}

    // encrypts data
    // output length is equal to input length
    virtual void encrypt(const byte *input, byte *output, const size_t length) =0;

    // decrypts data
    // output length is equal to input length
    virtual void decrypt(const byte *input, byte *output, const size_t length) =0;

    // encrypts a data block
    // input length must be equal to the cipher block size
    // output length is equal to input length
    virtual void encryptBlock(const byte *input, byte *output, const size_t length) =0;

    // decrypts a data block
    // input length must be equal to the cipher block size
    // output length is equal to input length
    virtual void decryptBlock(const byte *input, byte *output, const size_t length) =0;

    // returns Crypto++ objects used
    virtual CryptoPP::BlockCipher *getEncryptor() =0;
    virtual CryptoPP::BlockCipher *getDecryptor() =0;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_BLOCK_CIPHER_INTERFACE_H */
