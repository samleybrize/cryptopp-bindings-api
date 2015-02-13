
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_GCM_H
#define API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_GCM_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/block/api_block_cipher_interface.h"
#include "api_authenticated_symmetric_cipher_abstract.h"
#include <gcm.h>

NAMESPACE_BEGIN(CryptoppApi)

class CryptoppGcm
{
public:
    /* base class */
    class Base : public CryptoPP::GCM_Base
    {
    public:
        static std::string StaticAlgorithmName() {return std::string("GCM");}

    protected:
        Base(CryptoPP::BlockCipher *cipher)
            : m_cipher(cipher) {}

    private:
        CryptoPP::GCM_TablesOption GetTablesOption() const {return CryptoPP::GCM_2K_Tables;}
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

class AuthenticatedSymmetricCipherGcm : public AuthenticatedSymmetricCipherAbstract
{
public:
    AuthenticatedSymmetricCipherGcm(BlockCipherInterface *cipher);
    ~AuthenticatedSymmetricCipherGcm();

private:
    CryptoppGcm::Encryption *m_encryptor;
    CryptoppGcm::Decryption *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_GCM_H */
