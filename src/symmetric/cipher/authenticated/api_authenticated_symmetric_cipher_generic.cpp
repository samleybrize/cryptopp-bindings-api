
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_authenticated_symmetric_cipher_generic.h"
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

CryptoppAuthenticatedSymmetricCipherGeneric::Base::Base(CryptoPP::SymmetricCipher *cipher, CryptoPP::MessageAuthenticationCode *mac)
{
    m_cipher    = cipher;
    m_mac       = mac;
}

CryptoppAuthenticatedSymmetricCipherGeneric::Encryption::Encryption(CryptoPP::SymmetricCipher *cipher, CryptoPP::MessageAuthenticationCode *mac)
    : Base(cipher, mac)
{
    assert(cipher->IsForwardTransformation());
}

CryptoppAuthenticatedSymmetricCipherGeneric::Decryption::Decryption(CryptoPP::SymmetricCipher *cipher, CryptoPP::MessageAuthenticationCode *mac)
    : Base(cipher, mac)
{
    // can't assert that the cipher is not a forward transformation, because some ciphers use the same transformation for both encryption and decryption
}

void CryptoppAuthenticatedSymmetricCipherGeneric::Base::ProcessData(byte *outString, const byte *inString, size_t length)
{
    m_cipher->ProcessData(outString, inString, length);

    if (IsForwardTransformation()) {
        // encryption
        m_mac->Update(outString, length);
    } else {
        // decryption
        m_mac->Update(inString, length);
    }
}

// TODO
void CryptoppAuthenticatedSymmetricCipherGeneric::Base::SetKeyWithIV(const byte *key, size_t length, const byte *iv, size_t ivLength)
{
    m_cipher->SetKeyWithIV(key, length, iv, ivLength);
    m_mac->Restart();
}

// TODO
void CryptoppAuthenticatedSymmetricCipherGeneric::Base::SetKey(const byte *key, size_t length, const CryptoPP::NameValuePairs &params)
{
    m_cipher->SetKey(key, length, params);
    m_mac->Restart();
}

// TODO
void CryptoppAuthenticatedSymmetricCipherGeneric::Base::Resynchronize(const byte *iv, int ivLength)
{
    m_cipher->Resynchronize(iv, ivLength);
    m_mac->Restart();
}

// TODO
bool CryptoppAuthenticatedSymmetricCipherGeneric::Base::IsValidKeyLength(size_t n) const
{
    return m_cipher->IsValidKeyLength(n);
}

// TODO
void CryptoppAuthenticatedSymmetricCipherGeneric::Base::Restart()
{
    m_mac->Restart();

//    if (0 != dynamic_cast<SymmetricTransformationUserInterface*>(m_cipher)) {
//        dynamic_cast<SymmetricTransformationUserInterface*>(m_cipher)->Restart();
//    }
}

AuthenticatedSymmetricCipherGeneric::AuthenticatedSymmetricCipherGeneric(SymmetricModeInterface *mode, MacInterface *mac)
    : AuthenticatedSymmetricCipherAbstract()
    , m_cipher(mode)
    , m_mac(mac)
{
    // name
    std::string name(mode->getName());
    name.append("/");
    name.append(mac->getName());
    setName(name);

    // create cipher object
    m_encryptor = new CryptoppAuthenticatedSymmetricCipherGeneric::Encryption(mode->getEncryptor(), mac->getCryptoppObject());
    m_decryptor = new CryptoppAuthenticatedSymmetricCipherGeneric::Decryption(mode->getDecryptor(), mac->getCryptoppObject());
    setCryptoppObjects(m_encryptor, m_decryptor);
}

AuthenticatedSymmetricCipherGeneric::AuthenticatedSymmetricCipherGeneric(StreamCipherInterface *cipher, MacInterface *mac)
    : AuthenticatedSymmetricCipherAbstract()
    , m_cipher(cipher)
    , m_mac(mac)
{
    // name
    std::string name(cipher->getName());
    name.append("/");
    name.append(mac->getName());
    setName(name);

    // create cipher object
    m_encryptor = new CryptoppAuthenticatedSymmetricCipherGeneric::Encryption(cipher->getEncryptor(), mac->getCryptoppObject());
    m_decryptor = new CryptoppAuthenticatedSymmetricCipherGeneric::Decryption(cipher->getDecryptor(), mac->getCryptoppObject());
    setCryptoppObjects(m_encryptor, m_decryptor);
}

AuthenticatedSymmetricCipherGeneric::~AuthenticatedSymmetricCipherGeneric()
{
    delete m_encryptor;
    delete m_decryptor;
}

void AuthenticatedSymmetricCipherGeneric::restart()
{
    if (!isValidKeyLength(getKeyLength()) || !isValidIvLength(getIvLength()) || !isValidMacKeyLength(getMacKeyLength())) {
        return;
    }

    m_cipher->restart();
    m_mac->restart();
}

NAMESPACE_END
