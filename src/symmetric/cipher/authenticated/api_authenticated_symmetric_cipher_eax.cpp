
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_authenticated_symmetric_cipher_eax.h"

NAMESPACE_BEGIN(CryptoppApi)

AuthenticatedSymmetricCipherEax::AuthenticatedSymmetricCipherEax(BlockCipherInterface *cipher)
    : AuthenticatedSymmetricCipherAbstract()
{
    // name
    std::string name("eax(");
    name.append(cipher->getName());
    name.append(")");
    setName(name);

    // create cipher object
    m_encryptor = new CryptoppApiInternal::CryptoppEax::Encryption(cipher->getEncryptor());
    m_decryptor = new CryptoppApiInternal::CryptoppEax::Decryption(cipher->getEncryptor());
    setCryptoppObjects(m_encryptor, m_decryptor);
    setCipherObject(cipher);
}

AuthenticatedSymmetricCipherEax::~AuthenticatedSymmetricCipherEax()
{
    delete m_encryptor;
    delete m_decryptor;
}

NAMESPACE_END
