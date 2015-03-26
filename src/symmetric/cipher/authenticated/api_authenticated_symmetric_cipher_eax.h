
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_EAX_H
#define API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_EAX_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/block/api_block_cipher_interface.h"
#include "api_authenticated_symmetric_cipher_abstract.h"
#include <eax.h>

NAMESPACE_BEGIN(CryptoppApi)

// internal namespace
NAMESPACE_BEGIN(CryptoppApiInternal)

// TODO comments
class CryptoppEaxCmac : public CryptoPP::CMAC_Base
{
public:
    CryptoppEaxCmac(CryptoPP::BlockCipher *cipher) : m_cipher(cipher) {assert(cipher->IsForwardTransformation());}
    size_t DefaultKeyLength() const {return m_cipher->DefaultKeyLength();}
    size_t MinKeyLength() const {return m_cipher->MinKeyLength();}
    size_t MaxKeyLength() const {return m_cipher->MaxKeyLength();}
    size_t GetValidKeyLength(size_t n) const {return m_cipher->GetValidKeyLength(n);}
    bool IsValidKeyLength(size_t n) const {return m_cipher->IsValidKeyLength(n);}
    IV_Requirement IVRequirement() const {return NOT_RESYNCHRONIZABLE;}

private:
    CryptoPP::BlockCipher & AccessCipher() {return *m_cipher;}
    CryptoPP::BlockCipher *m_cipher;
};

class CryptoppEax
{
public:
    /* base class */
    class Base : public CryptoPP::EAX_Base
    {
    public:
        ~Base() {delete m_cmac;}
        static std::string StaticAlgorithmName() {return std::string("EAX");}

    protected:
        Base(CryptoPP::BlockCipher *cipher)
            : m_cipher(cipher) {m_cmac = new CryptoppEaxCmac(cipher);}

    private:
        CryptoPP::BlockCipher & AccessBlockCipher() {return *m_cipher;}
        CryptoPP::CMAC_Base & AccessMAC() {return *m_cmac;}

        CryptoPP::BlockCipher *m_cipher;
        CryptoppEaxCmac *m_cmac;
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

NAMESPACE_END // CryptoppApiInternal

class AuthenticatedSymmetricCipherEax : public AuthenticatedSymmetricCipherAbstract
{
public:
    AuthenticatedSymmetricCipherEax(BlockCipherInterface *cipher);
    ~AuthenticatedSymmetricCipherEax();

private:
    CryptoppApiInternal::CryptoppEax::Encryption *m_encryptor;
    CryptoppApiInternal::CryptoppEax::Decryption *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_EAX_H */
