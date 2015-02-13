
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_authenticated_symmetric_cipher_gcm.h"

NAMESPACE_BEGIN(CryptoppApi)

AuthenticatedSymmetricCipherGcm::AuthenticatedSymmetricCipherGcm(BlockCipherInterface *cipher)
    : AuthenticatedSymmetricCipherAbstract()
{
    // name
    std::string name("gcm(");
    name.append(cipher->getName());
    name.append(")");
    setName(name);

    // create cipher object
    m_encryptor = new CryptoppGcm::Encryption(cipher->getEncryptor());
    m_decryptor = new CryptoppGcm::Decryption(cipher->getEncryptor());
    setCryptoppObjects(m_encryptor, m_decryptor);
}

AuthenticatedSymmetricCipherGcm::~AuthenticatedSymmetricCipherGcm()
{
    delete m_encryptor;
    delete m_decryptor;
}

NAMESPACE_END
