
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_symmetric_mode_abstract.h"
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

SymmetricModeAbstract::SymmetricModeAbstract()
    : m_cipher(NULL)
    , m_encryptor(NULL)
    , m_decryptor(NULL)
    , m_name("")
{
}

void SymmetricModeAbstract::setCryptoppObjects(BlockCipherInterface *cipher, CryptoPP::SymmetricCipher *encryptor, CryptoPP::SymmetricCipher *decryptor)
{
    m_cipher    = cipher;
    m_encryptor = encryptor;
    m_decryptor = decryptor;
}

const char *SymmetricModeAbstract::getName() const
{
    return m_name.c_str();
}

size_t SymmetricModeAbstract::getBlockSize() const
{
    return m_encryptor->MandatoryBlockSize();
}

bool SymmetricModeAbstract::isValidKeyLength(size_t length) const
{
    return m_encryptor->IsValidKeyLength(length);
}

bool SymmetricModeAbstract::isValidIvLength(size_t length) const
{
    bool isValid = false;

    if(!m_encryptor->IsResynchronizable()) {
        isValid = (0 == length);
    } else {
        isValid = length >= m_encryptor->MinIVLength() && length <= m_encryptor->MaxIVLength();
    }

    return isValid;
}

void SymmetricModeAbstract::setKey(const byte *key, const size_t keyLength)
{
    SymmetricKeyAbstract::setKey(key, keyLength);
    m_cipher->setKey(key, keyLength);
    restart();
}

void SymmetricModeAbstract::setIv(const byte *iv, const size_t ivLength)
{
    SymmetricIvAbstract::setIv(iv, ivLength);
    restart();
}

void SymmetricModeAbstract::setName(const std::string name)
{
    m_name.assign(name);
}

void SymmetricModeAbstract::setName(const std::string modeName, const std::string cipherName)
{
    std::string name(modeName);
    name.append("(");
    name.append(cipherName);
    name.append(")");
    setName(name);
}

void SymmetricModeAbstract::encrypt(const byte *input, byte *output, const size_t length)
{
    size_t blockSize = getBlockSize();

    // data size must be a multiple of the block size
    if (0 != length % blockSize) {
        std::stringstream msg;
        msg << "data size (" << length << ") is not a multiple of block size (" << blockSize << ")";
        throw Exception(msg.str());
    }

    // verify that key/iv are valid
    hasValidKey(true);
    hasValidIv(true);

    // verify that key is equals to underlying cipher key
    if (!isKeyEqualsTo(m_cipher)) {
        throw Exception("key is not matching the one owned by the underlying cipher object");
    }

    // encrypt
    m_encryptor->ProcessData(output, input, length);
}

void SymmetricModeAbstract::decrypt(const byte *input, byte *output, const size_t length)
{
    size_t blockSize = getBlockSize();

    // data size must be a multiple of the block size
    if (0 != length % blockSize) {
        std::stringstream msg;
        msg << "data size (" << length << ") is not a multiple of block size (" << blockSize << ")";
        throw Exception(msg.str());
    }

    // verify that key/iv are valid
    hasValidKey(true);
    hasValidIv(true);

    // verify that key is equals to underlying cipher key
    if (!isKeyEqualsTo(m_cipher)) {
        throw Exception("key is not matching the one owned by the underlying cipher object");
    }

    // decrypt
    m_decryptor->ProcessData(output, input, length);
}

void SymmetricModeAbstract::restart()
{
    size_t keyLength    = getKeyLength();
    size_t ivLength     = getIvLength();

    if (!isValidKeyLength(keyLength) || !isValidIvLength(ivLength)) {
        return;
    }

    byte key[keyLength];
    byte iv[ivLength];
    getKey(key);
    getIv(iv);

    if (m_encryptor->IsResynchronizable()) {
        m_encryptor->SetKeyWithIV(key, keyLength, iv, ivLength);
        m_decryptor->SetKeyWithIV(key, keyLength, iv, ivLength);
    } else {
        // mode does not need an IV
        m_encryptor->SetKey(key, keyLength);
        m_decryptor->SetKey(key, keyLength);
    }
}

NAMESPACE_END
