
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_symmetric_mode_ecb.h"
#include <string>

NAMESPACE_BEGIN(CryptoppApi)

SymmetricModeEcb::SymmetricModeEcb(BlockCipherInterface *cipher)
    : SymmetricModeAbstract()
{
    // name
    setName("ecb", cipher->getName());

    // create mode object
    m_encryptor = new CryptoPP::ECB_Mode_ExternalCipher::Encryption(cipher->getEncryptor());
    m_decryptor = new CryptoPP::ECB_Mode_ExternalCipher::Decryption(cipher->getDecryptor());
    setCryptoppObjects(m_encryptor, m_decryptor);
}

SymmetricModeEcb::~SymmetricModeEcb()
{
    delete m_encryptor;
    delete m_decryptor;
}

NAMESPACE_END
