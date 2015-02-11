
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_STREAM_CIPHER_SOSEMANUK_H
#define API_CRYPTOPP_STREAM_CIPHER_SOSEMANUK_H

#include "src/api_cryptopp.h"
#include "api_stream_cipher_abstract.h"
#include <sosemanuk.h>

NAMESPACE_BEGIN(CryptoppApi)

class StreamCipherSosemanuk : public StreamCipherAbstract
{
public:
    StreamCipherSosemanuk();

private:
    CryptoPP::Sosemanuk::Encryption m_encryptor;
    CryptoPP::Sosemanuk::Decryption m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_STREAM_CIPHER_SOSEMANUK_H */
