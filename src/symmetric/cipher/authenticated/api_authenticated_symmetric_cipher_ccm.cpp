
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_authenticated_symmetric_cipher_ccm.h"
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

AuthenticatedSymmetricCipherCcm::AuthenticatedSymmetricCipherCcm(BlockCipherInterface *cipher)
    : AuthenticatedSymmetricCipherAbstract()
    , m_dataSize(0)
    , m_aadSize(0)
    , m_digestSize(16)
    , m_processedEncryptionDataSize(0)
    , m_processedDecryptionDataSize(0)
    , m_processedEncryptionAadSize(0)
    , m_processedDecryptionAadSize(0)
{
    // name
    std::string name("ccm(");
    name.append(cipher->getName());
    name.append(")");
    setName(name);

    // check cipher block size
    if (16 != cipher->getBlockSize()) {
        throw Exception("CCM require a block cipher with a block size of 128 bits (16 bytes)");
    }

    // create cipher object
    m_encryptor = new CryptoppCcm::Encryption(cipher->getEncryptor());
    m_decryptor = new CryptoppCcm::Decryption(cipher->getEncryptor());
    setCryptoppObjects(cipher, m_encryptor, m_decryptor);

    // default digest size
    m_encryptor->SetDigestSize(m_digestSize);
    m_decryptor->SetDigestSize(m_digestSize);
}

AuthenticatedSymmetricCipherCcm::~AuthenticatedSymmetricCipherCcm()
{
    delete m_encryptor;
    delete m_decryptor;
}

void AuthenticatedSymmetricCipherCcm::setDigestSize(size_t digestSize)
{
    m_digestSize = digestSize;
    restart();
}

void AuthenticatedSymmetricCipherCcm::specifyDataSize(size_t dataSize, size_t aadSize)
{
    m_dataSize  = dataSize;
    m_aadSize   = aadSize;
    restart();
}

void AuthenticatedSymmetricCipherCcm::addEncryptionAdditionalData(const byte *data, size_t dataLength)
{
    if (m_processedEncryptionAadSize + dataLength > m_aadSize) {
        std::stringstream msg;
        msg << "AAD length doesn't match that given in specifyDataSize (" << m_aadSize << " expected, " << (m_processedEncryptionAadSize + dataLength) << " given)";
        throw Exception(msg.str());
    }

    AuthenticatedSymmetricCipherAbstract::addEncryptionAdditionalData(data, dataLength);
    m_processedEncryptionAadSize += dataLength;
}

void AuthenticatedSymmetricCipherCcm::addDecryptionAdditionalData(const byte *data, size_t dataLength)
{
    if (m_processedDecryptionAadSize + dataLength > m_aadSize) {
        std::stringstream msg;
        msg << "AAD length doesn't match that given in specifyDataSize (" << m_aadSize << " expected, " << (m_processedDecryptionAadSize + dataLength) << " given)";
        throw Exception(msg.str());
    }

    AuthenticatedSymmetricCipherAbstract::addDecryptionAdditionalData(data, dataLength);
    m_processedDecryptionAadSize += dataLength;
}

void AuthenticatedSymmetricCipherCcm::encrypt(const byte *input, byte *output, const size_t length)
{
    if (m_processedEncryptionDataSize + length > m_dataSize) {
        std::stringstream msg;
        msg << "message length doesn't match that given in specifyDataSize (" << m_dataSize << " expected, " << (m_processedEncryptionDataSize + length) << " given)";
        throw Exception(msg.str());
    } else if (m_processedEncryptionAadSize != m_aadSize) {
        std::stringstream msg;
        msg << "AAD length doesn't match that given in specifyDataSize (" << m_aadSize << " expected, " << m_processedEncryptionAadSize << " given)";
        throw Exception(msg.str());
    }

    AuthenticatedSymmetricCipherAbstract::encrypt(input, output, length);
    m_processedEncryptionDataSize += length;
}

void AuthenticatedSymmetricCipherCcm::decrypt(const byte *input, byte *output, const size_t length)
{
    if (m_processedDecryptionDataSize + length > m_dataSize) {
        std::stringstream msg;
        msg << "message length doesn't match that given in specifyDataSize (" << m_dataSize << " expected, " << (m_processedDecryptionDataSize + length) << " given)";
        throw Exception(msg.str());
    } else if (m_processedDecryptionAadSize != m_aadSize) {
        std::stringstream msg;
        msg << "AAD length doesn't match that given in specifyDataSize (" << m_aadSize << " expected, " << m_processedDecryptionAadSize << " given)";
        throw Exception(msg.str());
    }

    AuthenticatedSymmetricCipherAbstract::decrypt(input, output, length);
    m_processedDecryptionDataSize += length;
}

void AuthenticatedSymmetricCipherCcm::finalizeEncryption(byte *output)
{
    if (m_processedEncryptionDataSize > m_dataSize) {
        std::stringstream msg;
        msg << "message length doesn't match that given in specifyDataSize (" << m_dataSize << " expected, " << m_processedEncryptionDataSize << " given)";
        throw Exception(msg.str());
    } else if (m_processedEncryptionAadSize > m_aadSize) {
        std::stringstream msg;
        msg << "AAD length doesn't match that given in specifyDataSize (" << m_aadSize << " expected, " << m_processedEncryptionAadSize << " given)";
        throw Exception(msg.str());
    }

    AuthenticatedSymmetricCipherAbstract::finalizeEncryption(output);
}

void AuthenticatedSymmetricCipherCcm::finalizeDecryption(byte *output)
{
    if (m_processedDecryptionDataSize > m_dataSize) {
        std::stringstream msg;
        msg << "message length doesn't match that given in specifyDataSize (" << m_dataSize << " expected, " << m_processedDecryptionDataSize << " given)";
        throw Exception(msg.str());
    } else if (m_processedDecryptionAadSize > m_aadSize) {
        std::stringstream msg;
        msg << "AAD length doesn't match that given in specifyDataSize (" << m_aadSize << " expected, " << m_processedDecryptionAadSize << " given)";
        throw Exception(msg.str());
    }

    AuthenticatedSymmetricCipherAbstract::finalizeDecryption(output);
}

void AuthenticatedSymmetricCipherCcm::restart()
{
    if (!isValidKeyLength(getKeyLength()) || !isValidIvLength(getIvLength())) {
        return;
    }

    AuthenticatedSymmetricCipherAbstract::restart();

    m_encryptor->SetDigestSize(m_digestSize);
    m_decryptor->SetDigestSize(m_digestSize);
    m_encryptor->SpecifyDataLengths(m_aadSize, m_dataSize);
    m_decryptor->SpecifyDataLengths(m_aadSize, m_dataSize);

    m_processedEncryptionDataSize   = 0;
    m_processedDecryptionDataSize   = 0;
    m_processedEncryptionAadSize    = 0;
    m_processedDecryptionAadSize    = 0;
}

void CryptoppCcm::Base::SetDigestSize(int digestSize)
{
    if (digestSize % 2 > 0 || digestSize < 4 || digestSize > 16) {
        throw Exception("digest size must be 4, 6, 8, 10, 12, 14, or 16");
    }

    m_digestSize = digestSize;
}

NAMESPACE_END
