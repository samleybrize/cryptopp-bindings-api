
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

class CryptoppCcm
{
public:
    /* base class */
    class Base : public CryptoPP::CCM_Base
    {
    public:
        ~Base();
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

    /* encryption class */
    class Encryption : public Base
    {
    public:
        Encryption(CryptoPP::BlockCipher *cipher) : Base(cipher){};
        bool IsForwardTransformation() const {return true;}
    };

    /* decryption class */
    class Decryption : public Base
    {
    public:
        Decryption(CryptoPP::BlockCipher *cipher) : Base(cipher){};
        bool IsForwardTransformation() const {return false;}
    };
};

class AuthenticatedSymmetricCipherCcm : public AuthenticatedSymmetricCipherAbstract
{
public:
    AuthenticatedSymmetricCipherCcm(BlockCipherInterface *cipher);
    ~AuthenticatedSymmetricCipherCcm();

    void setDigestSize(size_t digestSize);
    void specifyDataSize(size_t dataSize, size_t aadSize);
    void addEncryptionAdditionalData(byte *data, size_t dataLength);
    void addDecryptionAdditionalData(byte *data, size_t dataLength);
    void encrypt(const byte *input, byte *output, const size_t length);
    void decrypt(const byte *input, byte *output, const size_t length);
    void finalizeEncryption(byte *output);
    void finalizeDecryption(byte *output);
    void restart();

private:
    size_t m_digestSize;
    size_t m_dataSize;
    size_t m_aadSize;
    size_t m_processedEncryptionDataSize;
    size_t m_processedDecryptionDataSize;
    size_t m_processedEncryptionAadSize;
    size_t m_processedDecryptionAadSize;
    CryptoppCcm::Encryption *m_encryptor;
    CryptoppCcm::Decryption *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_CCM_H */
