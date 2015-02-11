
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_stream_cipher_sosemanuk.h"

NAMESPACE_BEGIN(CryptoppApi)

StreamCipherSosemanuk::StreamCipherSosemanuk()
    : StreamCipherAbstract()
{
    setName("sosemanuk");
    setCryptoppObjects(&m_encryptor, &m_decryptor);
}

NAMESPACE_END
