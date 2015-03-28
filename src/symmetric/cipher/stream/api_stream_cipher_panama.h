
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_STREAM_CIPHER_PANAMA_H
#define API_CRYPTOPP_STREAM_CIPHER_PANAMA_H

#include "src/api_cryptopp.h"
#include "src/api_endianness.h"
#include "api_stream_cipher_abstract.h"

NAMESPACE_BEGIN(CryptoppApi)

class StreamCipherPanama : public StreamCipherAbstract
{
public:
    // default constructor
    // init the cipher with little endian
    StreamCipherPanama() : StreamCipherAbstract()
        {init(Endianness::E_LITTLE_ENDIAN);}

    // constructor that permit to specify endianness
    StreamCipherPanama(Endianness endianness) : StreamCipherAbstract()
        {init(endianness);}

    ~StreamCipherPanama();

private:
    // init object
    // called once by the constructor
    void init(Endianness endianness);

    CryptoPP::SymmetricCipher *m_encryptor;
    CryptoPP::SymmetricCipher *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_STREAM_CIPHER_PANAMA_H */
