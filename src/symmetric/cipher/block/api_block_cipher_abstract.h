
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_BLOCK_CIPHER_ABSTRACT_H
#define API_CRYPTOPP_BLOCK_CIPHER_ABSTRACT_H

#include "src/api_cryptopp.h"
#include "api_block_cipher_interface.h"
#include <string>

NAMESPACE_BEGIN(CryptoppApi)

// Abstract class for block cipher classes that define common tasks
class BlockCipherAbstract : public BlockCipherInterface
{
public:
    // TODO comments
    using SymmetricKeyAbstract::isValidKeyLength;

    const char *getName() const;
    size_t getBlockSize() const;
    bool isValidKeyLength(size_t length) const;
    void setKey(const byte *key, const size_t keyLength);
    void encrypt(const byte *input, byte *output, const size_t length);
    void decrypt(const byte *input, byte *output, const size_t length);
    void encryptBlock(const byte *input, byte *output, const size_t length);
    void decryptBlock(const byte *input, byte *output, const size_t length);

    CryptoPP::BlockCipher *getEncryptor() {return m_encryptor;}
    CryptoPP::BlockCipher *getDecryptor() {return m_decryptor;}

protected:
    // TODO comments
    BlockCipherAbstract();
    void setCryptoppObjects(CryptoPP::BlockCipher *encryptor, CryptoPP::BlockCipher *decryptor);
    void setName(const std::string name);

private:
    // TODO comments
    std::string m_name;
    CryptoPP::BlockCipher *m_encryptor;
    CryptoPP::BlockCipher *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_BLOCK_CIPHER_ABSTRACT_H */
