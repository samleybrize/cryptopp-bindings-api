
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_symmetric_mode_ctr.h"
#include <string>

NAMESPACE_BEGIN(CryptoppApi)

SymmetricModeCtr::SymmetricModeCtr(BlockCipherInterface *cipher)
    : SymmetricModeAbstract()
{
    // name
    setName("ctr", cipher->getName());

    // create mode object
    size_t blockSize = cipher->getBlockSize();
    byte dummyIv[blockSize];

    m_encryptor = new CryptoPP::CTR_Mode_ExternalCipher::Encryption(cipher->getEncryptor(), dummyIv, blockSize);
    m_decryptor = new CryptoPP::CTR_Mode_ExternalCipher::Decryption(cipher->getEncryptor(), dummyIv, blockSize);
    setCryptoppObjects(m_encryptor, m_decryptor);
}

SymmetricModeCtr::~SymmetricModeCtr()
{
    delete m_encryptor;
    delete m_decryptor;
}

NAMESPACE_END
