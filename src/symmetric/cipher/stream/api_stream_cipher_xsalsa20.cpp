
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
        throw Exception("number of rounds must be one of 8, 12 or 20");
    }

    m_rounds = rounds;
    m_encryptor.SetRounds(rounds);
    m_decryptor.SetRounds(rounds);

    // restart
    restart();
}

void CryptoppApiInternal::CryptoppXSalsa20Encryption::SetRounds(int rounds)
{
    m_rounds = rounds;
}

void CryptoppApiInternal::CryptoppXSalsa20Decryption::SetRounds(int rounds)
{
    m_rounds = rounds;
}

void CryptoppApiInternal::CryptoppXSalsa20Encryption::CipherSetKey(const CryptoPP::NameValuePairs &params, const byte *key, size_t length)
{
    int rounds = m_rounds;
    CryptoPP::XSalsa20::Encryption::CipherSetKey(params, key, length);

    if (rounds > 0) {
        m_rounds = rounds;
    }
}

void CryptoppApiInternal::CryptoppXSalsa20Decryption::CipherSetKey(const CryptoPP::NameValuePairs &params, const byte *key, size_t length)
{
    int rounds = m_rounds;
    CryptoPP::XSalsa20::Decryption::CipherSetKey(params, key, length);

    if (rounds > 0) {
        m_rounds = rounds;
    }
}

NAMESPACE_END
