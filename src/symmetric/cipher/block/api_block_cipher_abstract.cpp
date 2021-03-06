
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
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

BlockCipherAbstract::BlockCipherAbstract()
    : m_encryptor(NULL)
    , m_decryptor(NULL)
    , m_name("")
{
}

void BlockCipherAbstract::setCryptoppObjects(CryptoPP::BlockCipher *encryptor, CryptoPP::BlockCipher *decryptor)
{
    m_encryptor = encryptor;
    m_decryptor = decryptor;
}

const char *BlockCipherAbstract::getName() const
{
    return m_name.c_str();
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
    SymmetricKeyAbstract::setKey(key, keyLength);

    // copy key
    byte keyCopy[keyLength];
    getKey(keyCopy);

    m_encryptor->SetKey(keyCopy, keyLength);
    m_decryptor->SetKey(keyCopy, keyLength);
}

void BlockCipherAbstract::setName(const std::string name)
{
    m_name.assign(name);
}

void BlockCipherAbstract::encrypt(const byte *input, byte *output, const size_t length)
{
    size_t blockSize = getBlockSize();

    // data size must be a multiple of the block size
    if (0 != length % blockSize) {
        std::stringstream msg;
        msg << "data size (" << length << ") is not a multiple of block size (" << blockSize << ")";
        throw Exception(msg.str());
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
        std::stringstream msg;
        msg << "data size (" << length << ") is not a multiple of block size (" << blockSize << ")";
        throw Exception(msg.str());
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
        std::stringstream msg;
        msg << "data size (" << length << ") is not equal to cipher block size (" << blockSize << ")";
        throw Exception(msg.str());
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
        std::stringstream msg;
        msg << "data size (" << length << ") is not equal to cipher block size (" << blockSize << ")";
        throw Exception(msg.str());
    }

    // verify that the key is valid
    hasValidKey(true);

    m_decryptor->ProcessAndXorBlock(block, NULL, output);
}

NAMESPACE_END
