
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_STREAM_CIPHER_XSALSA20_H
#define API_CRYPTOPP_STREAM_CIPHER_XSALSA20_H

#include "src/api_cryptopp.h"
#include "api_stream_cipher_abstract.h"
#include <salsa.h>

NAMESPACE_BEGIN(CryptoppApi)

class StreamCipherXSalsa20 : public StreamCipherAbstract
{
public:
    StreamCipherXSalsa20(int rounds);
    void setRounds(int rounds);
    void restart();

private:
    CryptoPP::XSalsa20::Encryption m_encryptor;
    CryptoPP::XSalsa20::Decryption m_decryptor;
    int m_rounds;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_STREAM_CIPHER_XSALSA20_H */
