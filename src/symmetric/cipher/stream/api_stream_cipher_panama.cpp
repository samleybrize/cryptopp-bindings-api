
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_stream_cipher_panama.h"
#include <panama.h>

NAMESPACE_BEGIN(CryptoppApi)

void StreamCipherPanama::init(Endianness endianness)
{
    setName("panama");

    if (Endianness::E_LITTLE_ENDIAN == endianness) {
        m_encryptor = new CryptoPP::PanamaCipher<CryptoPP::LittleEndian>::Encryption();
        m_decryptor = new CryptoPP::PanamaCipher<CryptoPP::LittleEndian>::Decryption();
    } else if (Endianness::E_BIG_ENDIAN == endianness) {
        m_encryptor = new CryptoPP::PanamaCipher<CryptoPP::BigEndian>::Encryption();
        m_decryptor = new CryptoPP::PanamaCipher<CryptoPP::BigEndian>::Decryption();
    } else {
        throw Exception("invalid endianness");
    }

    setCryptoppObjects(m_encryptor, m_decryptor);
}

StreamCipherPanama::~StreamCipherPanama()
{
    delete m_encryptor;
    delete m_decryptor;
}

NAMESPACE_END
