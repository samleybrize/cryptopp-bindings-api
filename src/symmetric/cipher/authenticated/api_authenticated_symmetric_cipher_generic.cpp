
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

CryptoppApiInternal::CryptoppAuthenticatedSymmetricCipherGeneric::Base::Base(CryptoPP::SymmetricCipher *cipher, CryptoPP::MessageAuthenticationCode *mac)
{
    m_cipher    = cipher;
    m_mac       = mac;
}

CryptoppApiInternal::CryptoppAuthenticatedSymmetricCipherGeneric::Encryption::Encryption(CryptoPP::SymmetricCipher *cipher, CryptoPP::MessageAuthenticationCode *mac)
    : Base(cipher, mac)
{
    assert(cipher->IsForwardTransformation());
}

CryptoppApiInternal::CryptoppAuthenticatedSymmetricCipherGeneric::Decryption::Decryption(CryptoPP::SymmetricCipher *cipher, CryptoPP::MessageAuthenticationCode *mac)
    : Base(cipher, mac)
{
    // can't assert that the cipher is not a forward transformation, because some ciphers use the same transformation for both encryption and decryption
}

void CryptoppApiInternal::CryptoppAuthenticatedSymmetricCipherGeneric::Base::ProcessData(byte *outString, const byte *inString, size_t length)
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
    m_encryptor = new CryptoppApiInternal::CryptoppAuthenticatedSymmetricCipherGeneric::Encryption(mode->getEncryptor(), mac->getCryptoppObject());
    m_decryptor = new CryptoppApiInternal::CryptoppAuthenticatedSymmetricCipherGeneric::Decryption(mode->getDecryptor(), mac->getCryptoppObject());
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
    m_encryptor = new CryptoppApiInternal::CryptoppAuthenticatedSymmetricCipherGeneric::Encryption(cipher->getEncryptor(), mac->getCryptoppObject());
    m_decryptor = new CryptoppApiInternal::CryptoppAuthenticatedSymmetricCipherGeneric::Decryption(cipher->getDecryptor(), mac->getCryptoppObject());
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

bool AuthenticatedSymmetricCipherGeneric::hasValidMacKey(bool throwIfFalse)
{
    try {
        return m_mac->isValidKeyLength(m_mac->getKeyLength(), true);
    } catch (Exception &e) {
        // replace "key" with "MAC key" and re-throw
        std::string msg = e.getMessage();
        msg.replace(msg.find("key"), 3, "MAC key");
        throw Exception(msg);
    }

    return false;
}

bool AuthenticatedSymmetricCipherGeneric::hasValidKey(bool throwIfFalse)
{
    if (!m_cipher->isValidKeyLength(m_cipher->getKeyLength(), true) || !hasValidMacKey(true)) {
        return false;
    }

    return true;
}

NAMESPACE_END
