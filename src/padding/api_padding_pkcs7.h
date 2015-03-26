
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_PADDING_PKCS7_H
#define API_CRYPTOPP_PADDING_PKCS7_H

#include "src/api_cryptopp.h"
#include "api_padding_interface.h"

NAMESPACE_BEGIN(CryptoppApi)

// PKCS#7 padding scheme implementation
class PaddingPkcs7 : public PaddingInterface
{
public:
    void pad(const size_t blockSize, const byte *input, const size_t inputLength, byte **output, size_t &outputLength);
    void unpad(const size_t blockSize, const byte *input, const size_t inputLength, byte **output, size_t &outputLength);
    bool canPad() {return true;}
    bool canUnpad() {return true;}
};

NAMESPACE_END

#endif /* API_CRYPTOPP_PADDING_PKCS7_H */
