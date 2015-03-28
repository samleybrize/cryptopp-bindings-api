
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_CCM_H
#define API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_CCM_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/block/api_block_cipher_interface.h"
#include "api_authenticated_symmetric_cipher_abstract.h"
#include <ccm.h>

NAMESPACE_BEGIN(CryptoppApi)

// internal namespace
NAMESPACE_BEGIN(CryptoppApiInternal)

// Fork of the Crypto++ implementation of CCM
// Allow to give a cipher object as a constructor parameter, and to specify the digest length and data lengths
class CryptoppCcm
{
public:
    // base class
    class Base : public CryptoPP::CCM_Base
    {
    public:
        void SetDigestSize(int digestSize);
        static std::string StaticAlgorithmName() {return std::string("CCM");}

    protected:
        Base(CryptoPP::BlockCipher *cipher)
            : m_cipher(cipher) {}
        int DefaultDigestSize() const {return DigestSize();}

    private:
        CryptoPP::BlockCipher & AccessBlockCipher() {return *m_cipher;}

        CryptoPP::BlockCipher *m_cipher;
    };

    // encryption class
    class Encryption : public Base
    {
    public:
        Encryption(CryptoPP::BlockCipher *cipher) : Base(cipher){};
        bool IsForwardTransformation() const {return true;}
    };

    // decryption class
    class Decryption : public Base
    {
    public:
        Decryption(CryptoPP::BlockCipher *cipher) : Base(cipher){};
        bool IsForwardTransformation() const {return false;}
    };
};

NAMESPACE_END // CryptoppApiInternal

// CCM authenticated cipher mode scheme implementation
class AuthenticatedSymmetricCipherCcm : public AuthenticatedSymmetricCipherAbstract
{
public:
    AuthenticatedSymmetricCipherCcm(BlockCipherInterface *cipher);
    ~AuthenticatedSymmetricCipherCcm();

    void addEncryptionAdditionalData(const byte *data, size_t dataLength);
    void addDecryptionAdditionalData(const byte *data, size_t dataLength);
    void encrypt(const byte *input, byte *output, const size_t length);
    void decrypt(const byte *input, byte *output, const size_t length);
    void finalizeEncryption(byte *output);
    void finalizeDecryption(byte *output);
    void restart();

    // sets the digest size
    // restarts current encryption/decryption state
    void setDigestSize(size_t digestSize);

    // specify data and AAD sizes
    // restarts current encryption/decryption state
    void specifyDataSize(size_t dataSize, size_t aadSize);

private:
    // digest size
    size_t m_digestSize;

    // data size
    size_t m_dataSize;

    // AAD size
    size_t m_aadSize;

    // encrypted data length since the last call to 'restart()' (or the construction of the object)
    size_t m_processedEncryptionDataSize;

    // decrypted data length since the last call to 'restart()' (or the construction of the object)
    size_t m_processedDecryptionDataSize;

    // processed AAD length (encryption) since the last call to 'restart()' (or the construction of the object)
    size_t m_processedEncryptionAadSize;

    // processed AAD length (decryption) since the last call to 'restart()' (or the construction of the object)
    size_t m_processedDecryptionAadSize;

    // Crypto++ objects used
    CryptoppApiInternal::CryptoppCcm::Encryption *m_encryptor;
    CryptoppApiInternal::CryptoppCcm::Decryption *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_CCM_H */
