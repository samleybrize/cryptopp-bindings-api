
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
    : m_encryptor(NULL)
    , m_decryptor(NULL)
    , m_name(NULL)
    , m_key(NULL)
    , m_keyLength(0)
    , m_iv(NULL)
    , m_ivLength(0)
{
}

SymmetricModeAbstract::~SymmetricModeAbstract()
{
    delete[] m_key;
    delete[] m_iv;
}

void SymmetricModeAbstract::setCryptoppObjects(CryptoPP::SymmetricCipher *encryptor, CryptoPP::SymmetricCipher *decryptor)
{
    m_encryptor = encryptor;
    m_decryptor = decryptor;
}

const char *SymmetricModeAbstract::getName() const
{
    return m_name;
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
    // verify that the key is valid
    isValidKeyLength(keyLength, true);

    // free key
    if (NULL != m_key) {
        delete[] m_key;
    }

    // copy the key
    m_keyLength = keyLength;
    m_key       = new byte[keyLength];
    memcpy(m_key, key, keyLength);

    // restart cipher
    restart();
}

void SymmetricModeAbstract::setIv(const byte *iv, const size_t ivLength)
{
    // verify that the iv is valid
    isValidIvLength(ivLength, true);

    // free iv
    if (NULL != m_iv) {
        delete[] m_iv;
    }

    // copy the iv
    m_ivLength  = ivLength;
    m_iv        = new byte[ivLength];
    memcpy(m_iv, iv, ivLength);

    // restart cipher
    restart();
}

void SymmetricModeAbstract::getKey(byte *key)
{
    memcpy(key, m_key, m_keyLength);
}

void SymmetricModeAbstract::getIv(byte *iv)
{
    memcpy(iv, m_iv, m_ivLength);
}

void SymmetricModeAbstract::setName(const std::string name)
{
    m_name = const_cast<char*>(name.c_str());
}

void SymmetricModeAbstract::encrypt(const byte *input, byte *output, const size_t length)
{
    size_t blockSize = getBlockSize();

    // data size must be a multiple of the block size
    if (0 != length % blockSize) {
        std::stringstream msg;
        msg << "data size (" << length << ") is not a multiple of block size (" << blockSize << ")";
        throw new Exception(msg.str());
    }

    // verify that key/iv are valid
    hasValidKey(true);
    hasValidIv(true);

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
        throw new Exception(msg.str());
    }

    // verify that key/iv are valid
    hasValidKey(true);
    hasValidIv(true);

    // decrypt
    m_decryptor->ProcessData(output, input, length);
}

void SymmetricModeAbstract::restart()
{
    if (!isValidKeyLength(m_keyLength) || !isValidIvLength(m_ivLength)) {
        return;
    }

    m_encryptor->SetKeyWithIV(m_key, m_keyLength, m_iv, m_ivLength);
    m_decryptor->SetKeyWithIV(m_key, m_keyLength, m_iv, m_ivLength);
}

NAMESPACE_END
