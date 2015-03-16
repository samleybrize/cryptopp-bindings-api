
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_symmetric_mode_cfb.h"
#include <string>

NAMESPACE_BEGIN(CryptoppApi)

SymmetricModeCfb::SymmetricModeCfb(BlockCipherInterface *cipher)
    : SymmetricModeAbstract()
{
    // name
    setName("cfb", cipher->getName());

    // create mode object
    m_encryptor = new CryptoppCfbEncryption();
    m_decryptor = new CryptoppCfbDecryption();
    m_encryptor->SetCipher(*cipher->getEncryptor());
    m_decryptor->SetCipher(*cipher->getEncryptor());
    setCryptoppObjects(cipher, m_encryptor, m_decryptor);
}

SymmetricModeCfb::~SymmetricModeCfb()
{
    delete m_encryptor;
    delete m_decryptor;
}

void CryptoppCfbEncryption::SetCipher(CryptoPP::BlockCipher &cipher)
{
    m_cipher = &cipher;
    ResizeBuffers();
}

void CryptoppCfbDecryption::SetCipher(CryptoPP::BlockCipher &cipher)
{
    m_cipher = &cipher;
    ResizeBuffers();
}

NAMESPACE_END
