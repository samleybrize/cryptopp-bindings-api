
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

NAMESPACE_BEGIN(CryptoppApi)

StreamCipherAbstract::StreamCipherAbstract(CryptoPP::SymmetricCipher &encryptor, CryptoPP::SymmetricCipher &decryptor)
    : m_encryptor(&encryptor)
    , m_decryptor(&decryptor)
    , m_name(NULL)
    , m_key(NULL)
    , m_keyLength(0)
    , m_iv(NULL)
    , m_ivLength(0)
{
}

StreamCipherAbstract::~StreamCipherAbstract()
{
    delete[] m_key;
    delete[] m_iv;
}

const char *StreamCipherAbstract::getName() const
{
    return m_name;
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
    // verify that the key is valid
    isValidKeyLength(keyLength, true);

    // copy the key
    m_keyLength = keyLength;
    m_key       = new byte[keyLength];
    memcpy(m_key, key, keyLength);

    // restart cipher
    restart();
}

void StreamCipherAbstract::setIv(const byte *iv, const size_t ivLength)
{
    // verify that the iv is valid
    isValidIvLength(ivLength, true);

    // copy the iv
    m_ivLength  = ivLength;
    m_iv        = new byte[ivLength];
    memcpy(m_iv, iv, ivLength);

    // restart cipher
    restart();
}

void StreamCipherAbstract::getKey(byte **key, size_t &length)
{
    *key    = new byte[m_keyLength];
    length  = m_keyLength;
    memcpy(*key, m_key, length);
}

void StreamCipherAbstract::getIv(byte **iv, size_t &length)
{
    *iv     = new byte[m_ivLength];
    length  = m_ivLength;
    memcpy(*iv, m_iv, length);
}

void StreamCipherAbstract::setName(const std::string name)
{
    m_name = const_cast<char*>(name.c_str());
}

void StreamCipherAbstract::encrypt(const byte *input, byte *output, const size_t length)
{
    size_t blockSize = getBlockSize();

    // data size must be a multiple of the block size
    if (0 != length % blockSize) {
        throw new Exception("data size (" << length << ") is not a multiple of block size (" << blockSize << ")");
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
        throw new Exception("data size (" << length << ") is not a multiple of block size (" << blockSize << ")");
    }

    // verify that key/iv are valid
    hasValidKey(true);
    hasValidIv(true);

    // decrypt
    m_decryptor->ProcessData(output, input, length);
}

void StreamCipherAbstract::restart()
{
    if (!isValidKeyLength(m_keyLength) || !isValidIvLength(m_ivLength)) {
        return;
    }

    m_encryptor->SetKeyWithIV(m_key, m_keyLength, m_iv, m_ivLength);
    m_decryptor->SetKeyWithIV(m_key, m_keyLength, m_iv, m_ivLength);
}

NAMESPACE_END
