
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

// internal namespace
NAMESPACE_BEGIN(CryptoppApiInternal)

// Fork of the Crypto++ implementation of Salsa20 (encryption part)
// Allow to set the number of rounds
class CryptoppSalsa20Encryption : public CryptoPP::Salsa20::Encryption
{
public:
    void SetRounds(int rounds);
    void CipherSetKey(const CryptoPP::NameValuePairs &params, const byte *key, size_t length);
};

// Fork of the Crypto++ implementation of Salsa20 (decryption part)
// Allow to set the number of rounds
class CryptoppSalsa20Decryption : public CryptoPP::Salsa20::Decryption
{
public:
    void SetRounds(int rounds);
    void CipherSetKey(const CryptoPP::NameValuePairs &params, const byte *key, size_t length);
};

NAMESPACE_END // CryptoppApiInternal

class StreamCipherSalsa20 : public StreamCipherAbstract
{
public:
    // default constructor
    // init the object with 20 rounds
    StreamCipherSalsa20() : StreamCipherAbstract()
        {init(20);}

    // constructor that allow to specify the numer of rounds
    // must be one of 8, 12 or 20
    StreamCipherSalsa20(int rounds) : StreamCipherAbstract()
        {init(rounds);}

    // sets the number of rounds
    // must be one of 8, 12 or 20
    void setRounds(int rounds);

private:
    // inits the object
    // 'rounds' must be one of 8, 12 or 20
    void init(int rounds);

    // Crypto++ objects used
    CryptoppApiInternal::CryptoppSalsa20Encryption m_encryptor;
    CryptoppApiInternal::CryptoppSalsa20Decryption m_decryptor;

    // number of rounds
    int m_rounds;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_STREAM_CIPHER_SALSA20_H */
