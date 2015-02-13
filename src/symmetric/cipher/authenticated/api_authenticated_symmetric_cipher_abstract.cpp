
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_authenticated_symmetric_cipher_abstract.h"
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

AuthenticatedSymmetricCipherAbstract::AuthenticatedSymmetricCipherAbstract()
    : m_encryptor(NULL)
    , m_decryptor(NULL)
    , m_encryptionStarted(false)
    , m_decryptionStarted(false)
    , m_name(NULL)
{
}

void AuthenticatedSymmetricCipherAbstract::setCryptoppObjects(CryptoPP::AuthenticatedSymmetricCipher *encryptor, CryptoPP::AuthenticatedSymmetricCipher *decryptor)
{
    m_encryptor = encryptor;
    m_decryptor = decryptor;
}

const char *AuthenticatedSymmetricCipherAbstract::getName() const
{
    return m_name;
}

size_t AuthenticatedSymmetricCipherAbstract::getBlockSize() const
{
    return m_encryptor->MandatoryBlockSize();
}

size_t AuthenticatedSymmetricCipherAbstract::getDigestSize() const
{
    return m_encryptor->DigestSize();
}

bool AuthenticatedSymmetricCipherAbstract::isValidKeyLength(size_t length) const
{
    return m_encryptor->IsValidKeyLength(length);
}

bool AuthenticatedSymmetricCipherAbstract::isValidIvLength(size_t length) const
{
    bool isValid = false;

    if(!m_encryptor->IsResynchronizable()) {
        isValid = (0 == length);
    } else {
        isValid = length >= m_encryptor->MinIVLength() && length <= m_encryptor->MaxIVLength();
    }

    return isValid;
}

void AuthenticatedSymmetricCipherAbstract::setKey(const byte *key, const size_t keyLength)
{
    SymmetricKeyAbstract::setKey(key, keyLength);
    restart();
}

void AuthenticatedSymmetricCipherAbstract::setIv(const byte *iv, const size_t ivLength)
{
    SymmetricIvAbstract::setIv(iv, ivLength);
    restart();
}

void AuthenticatedSymmetricCipherAbstract::setName(const std::string name)
{
    m_name = const_cast<char*>(name.c_str());
}

void AuthenticatedSymmetricCipherAbstract::addEncryptionAdditionalData(byte *data, size_t dataLength)
{
    if (m_encryptionStarted) {
        throw new Exception("additional authenticated data must be added before any encryption");
    }

    m_encryptor->Update(data, dataLength);
}

void AuthenticatedSymmetricCipherAbstract::addDecryptionAdditionalData(byte *data, size_t dataLength)
{
    if (m_decryptionStarted) {
        throw new Exception("additional authenticated data must be added before any decryption");
    }

    m_decryptor->Update(data, dataLength);
}

void AuthenticatedSymmetricCipherAbstract::encrypt(const byte *input, byte *output, const size_t length)
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
    m_encryptionStarted = true;
}

void AuthenticatedSymmetricCipherAbstract::decrypt(const byte *input, byte *output, const size_t length)
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
    m_decryptionStarted = true;
}

void AuthenticatedSymmetricCipherAbstract::finalizeEncryption(byte *output)
{
    m_encryptor->Final(output);
    restart();
}

void AuthenticatedSymmetricCipherAbstract::finalizeDecryption(byte *output)
{
    m_decryptor->Final(output);
    restart();
}

void AuthenticatedSymmetricCipherAbstract::restart()
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
    m_encryptionStarted = false;
    m_decryptionStarted = false;
}

NAMESPACE_END
