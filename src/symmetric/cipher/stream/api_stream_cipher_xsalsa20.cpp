
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_stream_cipher_xsalsa20.h"
#include <salsa.h>

NAMESPACE_BEGIN(CryptoppApi)

StreamCipherXSalsa20::StreamCipherXSalsa20(int rounds)
    : StreamCipherAbstract()
    , m_rounds(20)
{
    setName("xsalsa20");
    setCryptoppObjects(&m_encryptor, &m_decryptor);
    setRounds(rounds);
}

void StreamCipherXSalsa20::setRounds(int rounds)
{
    // verify number of rounds
    if (8 != rounds && 12 != rounds && 20 != rounds) {
        throw new Exception("number of rounds must be one of 8, 12 or 20");
    }

    m_rounds = rounds;

    // restart
    restart();
}

void StreamCipherXSalsa20::restart()
{
    StreamCipherAbstract::restart();

    // set the number of rounds
    size_t keyLength = getKeyLength();
    byte key[keyLength];
    getKey(key);
    m_encryptor.SetKeyWithRounds(key, keyLength, m_rounds);
    m_decryptor.SetKeyWithRounds(key, keyLength, m_rounds);
}

NAMESPACE_END
