
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_STREAM_CIPHER_SALSA20_H
#define API_CRYPTOPP_STREAM_CIPHER_SALSA20_H

#include "src/api_cryptopp.h"
#include "api_stream_cipher_abstract.h"
#include <salsa.h>

NAMESPACE_BEGIN(CryptoppApi)

class CryptoppSalsa20Encryption : public CryptoPP::Salsa20::Encryption
{
public:
    void SetRounds(int rounds);
    void CipherSetKey(const CryptoPP::NameValuePairs &params, const byte *key, size_t length);
};

class CryptoppSalsa20Decryption : public CryptoPP::Salsa20::Decryption
{
public:
    void SetRounds(int rounds);
    void CipherSetKey(const CryptoPP::NameValuePairs &params, const byte *key, size_t length);
};

class StreamCipherSalsa20 : public StreamCipherAbstract
{
public:
    StreamCipherSalsa20() : StreamCipherSalsa20(20) {}
    StreamCipherSalsa20(int rounds);
    void setRounds(int rounds);

private:
    CryptoppSalsa20Encryption m_encryptor;
    CryptoppSalsa20Decryption m_decryptor;
    int m_rounds;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_STREAM_CIPHER_SALSA20_H */
