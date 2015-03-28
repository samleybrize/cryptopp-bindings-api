
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
#include "src/symmetric/cipher/block/api_block_cipher_interface.h"
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
    void addEncryptionAdditionalData(const byte *data, size_t dataLength);
    void addDecryptionAdditionalData(const byte *data, size_t dataLength);
    void encrypt(const byte *input, byte *output, const size_t length);
    void decrypt(const byte *input, byte *output, const size_t length);
    void finalizeEncryption(byte *output);
    void finalizeDecryption(byte *output);
    void restart();

    virtual CryptoPP::AuthenticatedSymmetricCipher *getEncryptor() {return m_encryptor;}
    virtual CryptoPP::AuthenticatedSymmetricCipher *getDecryptor() {return m_decryptor;}

protected:
    AuthenticatedSymmetricCipherAbstract();

    // sets Crypto++ objects used
    void setCryptoppObjects(CryptoPP::AuthenticatedSymmetricCipher *encryptor, CryptoPP::AuthenticatedSymmetricCipher *decryptor);

    // sets the cipher used
    void setCipherObject(BlockCipherInterface *cipher);

    // sets algorithm name
    void setName(const std::string name);

private:
    // algorithm name
    std::string m_name;

    // indicates if an encryption operation has been performed since the last call to 'restart()' (or object construction)
    bool m_encryptionStarted;

    // indicates if a decryption operation has been performed since the last call to 'restart()' (or object construction)
    bool m_decryptionStarted;

    // cipher used
    BlockCipherInterface *m_cipher;

    // Crypto++ objects used
    CryptoPP::AuthenticatedSymmetricCipher *m_encryptor;
    CryptoPP::AuthenticatedSymmetricCipher *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_ABSTRACT_H */
