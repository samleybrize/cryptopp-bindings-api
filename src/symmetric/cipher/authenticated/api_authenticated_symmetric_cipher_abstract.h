
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_ABSTRACT_H
#define API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_ABSTRACT_H

#include "src/api_cryptopp.h"
#include "api_authenticated_symmetric_cipher_interface.h"
#include <string>

NAMESPACE_BEGIN(CryptoppApi)

class AuthenticatedSymmetricCipherAbstract : public AuthenticatedSymmetricCipherInterface
{
public:
    using SymmetricKeyAbstract::isValidKeyLength;
    using SymmetricIvAbstract::isValidIvLength;

    const char *getName() const;
    size_t getBlockSize() const;
    size_t getDigestSize() const;
    bool isValidKeyLength(size_t length) const;
    bool isValidIvLength(size_t length) const;
    void setKey(const byte *key, const size_t keyLength);
    void setIv(const byte *iv, const size_t ivLength);
    void addEncryptionAdditionalData(byte *data, size_t dataLength);
    void addDecryptionAdditionalData(byte *data, size_t dataLength);
    void encrypt(const byte *input, byte *output, const size_t length);
    void decrypt(const byte *input, byte *output, const size_t length);
    void finalizeEncryption(byte *output);
    void finalizeDecryption(byte *output);
    void restart();

protected:
    AuthenticatedSymmetricCipherAbstract();
    void setCryptoppObjects(CryptoPP::AuthenticatedSymmetricCipher *encryptor, CryptoPP::AuthenticatedSymmetricCipher *decryptor);
    void setName(const std::string name);

private:
    char *m_name;
    bool m_encryptionStarted;
    bool m_decryptionStarted;
    CryptoPP::AuthenticatedSymmetricCipher *m_encryptor;
    CryptoPP::AuthenticatedSymmetricCipher *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_ABSTRACT_H */