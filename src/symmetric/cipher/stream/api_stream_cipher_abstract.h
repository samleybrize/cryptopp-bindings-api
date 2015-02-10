
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_STREAM_CIPHER_ABSTRACT_H
#define API_CRYPTOPP_STREAM_CIPHER_ABSTRACT_H

#include "src/api_cryptopp.h"
#include "api_stream_cipher_interface.h"
#include <string>

NAMESPACE_BEGIN(CryptoppApi)

class StreamCipherAbstract : public StreamCipherInterface
{
public:
    ~StreamCipherAbstract();

    const char *getName() const;
    size_t getBlockSize() const;
    bool isValidKeyLength(size_t length) const;
    bool isValidIvLength(size_t length) const;
    void setKey(const byte *key, const size_t keyLength);
    void setIv(const byte *iv, const size_t ivLength);
    void getKey(byte **key, size_t &length);
    void getIv(byte **iv, size_t &length);
    void encrypt(const byte *input, byte *output, const size_t length);
    void decrypt(const byte *input, byte *output, const size_t length);
    void restart();

protected:
    StreamCipherAbstract(CryptoPP::SymmetricCipher &encryptor, CryptoPP::SymmetricCipher &decryptor);
    void setName(const std::string name);
    size_t getKeyLength() {return m_keyLength;}
    size_t getIvLength() {return m_ivLength;}

private:
    char *m_name;
    CryptoPP::SymmetricCipher *m_encryptor;
    CryptoPP::SymmetricCipher *m_decryptor;
    byte *m_key;
    size_t m_keyLength;
    byte *m_iv;
    size_t m_ivLength;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_STREAM_CIPHER_ABSTRACT_H */
