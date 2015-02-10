
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_block_cipher_abstract.h"

NAMESPACE_BEGIN(CryptoppApi)

BlockCipherAbstract::BlockCipherAbstract(CryptoPP::BlockCipher &encryptor, CryptoPP::BlockCipher &decryptor)
    : m_encryptor(&encryptor)
    , m_decryptor(&decryptor)
    , m_name(NULL)
    , m_key(NULL)
    , m_keyLength(0)
{
}

BlockCipherAbstract::~BlockCipherAbstract()
{
    delete[] m_key;
}

const char *BlockCipherAbstract::getName() const
{
    return m_name;
}

size_t BlockCipherAbstract::getBlockSize() const
{
    return m_encryptor->BlockSize();
}

bool BlockCipherAbstract::isValidKeyLength(size_t length) const
{
    return m_encryptor->IsValidKeyLength(length);
}

void BlockCipherAbstract::setKey(const byte *key, const size_t keyLength)
{
    // verify that the key is valid
    isValidKeyLength(keyLength, true);

    // copy the key
    m_keyLength = keyLength;
    m_key       = new byte[keyLength];
    memcpy(m_key, key, keyLength);

    m_encryptor->SetKey(key, keyLength);
    m_decryptor->SetKey(key, keyLength);
}

void BlockCipherAbstract::getKey(byte **key, size_t &length)
{
    *key    = new byte[m_keyLength];
    length  = m_keyLength;
    memcpy(*key, m_key, length);
}

void BlockCipherAbstract::setName(const std::string name)
{
    m_name = const_cast<char*>(name.c_str());
}

void BlockCipherAbstract::encrypt(const byte *input, byte *output, const size_t length)
{
    size_t blockSize = getBlockSize();

    // data size must be a multiple of the block size
    if (0 != length % blockSize) {
        throw new Exception("data size (" << length << ") is not a multiple of block size (" << blockSize << ")");
    }

    // verify that the key is valid
    hasValidKey(true);

    // encrypt each blocks
    int blocks = length / blockSize;

    for (int i = 0; i < blocks; i++) {
        m_encryptor->ProcessAndXorBlock(&input[i * blockSize], NULL, &output[i * blockSize]);
    }
}

void BlockCipherAbstract::decrypt(const byte *input, byte *output, const size_t length)
{
    size_t blockSize = getBlockSize();

    // data size must be a multiple of the block size
    if (0 != length % blockSize) {
        throw new Exception("data size (" << length << ") is not a multiple of block size (" << blockSize << ")");
    }

    // verify that the key is valid
    hasValidKey(true);

    // decrypt each blocks
    int blocks = length / blockSize;

    for (int i = 0; i < blocks; i++) {
        m_decryptor->ProcessAndXorBlock(&input[i * blockSize], NULL, &output[i * blockSize]);
    }
}

void BlockCipherAbstract::encryptBlock(const byte *block, byte *output, const size_t length)
{
    size_t blockSize = getBlockSize();

    // data size must be exactly equals to the block size
    if (length != blockSize) {
        throw new Exception("data size (" << length << ") is not equal to cipher block size (" << blockSize << ")");
    }

    // verify that the key is valid
    hasValidKey(true);

    m_encryptor->ProcessAndXorBlock(block, NULL, output);
}

void BlockCipherAbstract::decryptBlock(const byte *block, byte *output, const size_t length)
{
    size_t blockSize = getBlockSize();

    // data size must be exactly equals to the block size
    if (length != blockSize) {
        throw new Exception("data size (" << length << ") is not equal to cipher block size (" << blockSize << ")");
    }

    // verify that the key is valid
    hasValidKey(true);

    m_decryptor->ProcessAndXorBlock(block, NULL, output);
}

NAMESPACE_END
