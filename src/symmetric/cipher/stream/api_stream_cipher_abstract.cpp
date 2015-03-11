
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_stream_cipher_abstract.h"
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

StreamCipherAbstract::StreamCipherAbstract()
    : m_encryptor(NULL)
    , m_decryptor(NULL)
    , m_name("")
{
}

void StreamCipherAbstract::setCryptoppObjects(CryptoPP::SymmetricCipher *encryptor, CryptoPP::SymmetricCipher *decryptor)
{
    m_encryptor = encryptor;
    m_decryptor = decryptor;
}

const char *StreamCipherAbstract::getName() const
{
    return m_name.c_str();
}

size_t StreamCipherAbstract::getBlockSize() const
{
    return m_encryptor->MandatoryBlockSize();
}

bool StreamCipherAbstract::isValidKeyLength(size_t length) const
{
    return m_encryptor->IsValidKeyLength(length);
}

bool StreamCipherAbstract::isValidIvLength(size_t length) const
{
    bool isValid = false;

    if(!m_encryptor->IsResynchronizable()) {
        isValid = (0 == length);
    } else {
        isValid = length >= m_encryptor->MinIVLength() && length <= m_encryptor->MaxIVLength();
    }

    return isValid;
}

void StreamCipherAbstract::setKey(const byte *key, const size_t keyLength)
{
    SymmetricKeyAbstract::setKey(key, keyLength);
    restart();
}

void StreamCipherAbstract::setIv(const byte *iv, const size_t ivLength)
{
    SymmetricIvAbstract::setIv(iv, ivLength);
    restart();
}

void StreamCipherAbstract::setName(const std::string name)
{
    m_name.assign(name);
}

void StreamCipherAbstract::encrypt(const byte *input, byte *output, const size_t length)
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

    // encrypt
    m_encryptor->ProcessData(output, input, length);
}

void StreamCipherAbstract::decrypt(const byte *input, byte *output, const size_t length)
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

    // decrypt
    m_decryptor->ProcessData(output, input, length);
}

void StreamCipherAbstract::restart()
{
    size_t keyLength    = getKeyLength();
    size_t ivLength     = getIvLength();

    if (!isValidKeyLength(keyLength) || !isValidIvLength(ivLength)) {
        return;
    }

    byte key[keyLength];
    byte iv[ivLength];
    m_encryptor->SetKeyWithIV(key, keyLength, iv, ivLength);
    m_decryptor->SetKeyWithIV(key, keyLength, iv, ivLength);
}

NAMESPACE_END
