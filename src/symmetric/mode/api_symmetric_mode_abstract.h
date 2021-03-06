
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_SYMMETRIC_MODE_ABSTRACT_H
#define API_CRYPTOPP_SYMMETRIC_MODE_ABSTRACT_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/block/api_block_cipher_interface.h"
#include "api_symmetric_mode_interface.h"
#include <string>

NAMESPACE_BEGIN(CryptoppApi)

// Abstract class for cipher mode of operation classes that define common tasks
class SymmetricModeAbstract : public SymmetricModeInterface
{
public:
    using SymmetricKeyAbstract::isValidKeyLength;
    using SymmetricIvAbstract::isValidIvLength;

    const char *getName() const;
    size_t getBlockSize() const;
    bool isValidKeyLength(size_t length) const;
    bool isValidIvLength(size_t length) const;
    void setKey(const byte *key, const size_t keyLength);
    void setIv(const byte *iv, const size_t ivLength);
    void encrypt(const byte *input, byte *output, const size_t length);
    void decrypt(const byte *input, byte *output, const size_t length);
    void restart();

    virtual CryptoPP::SymmetricCipher *getEncryptor() {return m_encryptor;}
    virtual CryptoPP::SymmetricCipher *getDecryptor() {return m_decryptor;}

protected:
    SymmetricModeAbstract();

    // sets Crypto++ objects used
    void setCryptoppObjects(BlockCipherInterface *cipher, CryptoPP::SymmetricCipher *encryptor, CryptoPP::SymmetricCipher *decryptor);

    // sets the cipher mode name
    void setName(const std::string name);

    // sets the cipher mode name from a cipher name
    void setName(const std::string modeName, const std::string cipherName);

private:
    // cipher mode name
    std::string m_name;

    // cipher used
    BlockCipherInterface *m_cipher;

    // Crypto++ objects used
    CryptoPP::SymmetricCipher *m_encryptor;
    CryptoPP::SymmetricCipher *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_MODE_ABSTRACT_H */
