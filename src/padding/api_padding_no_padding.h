
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_PADDING_NO_PADDING_H
#define API_CRYPTOPP_PADDING_NO_PADDING_H

#include "src/api_cryptopp.h"
#include "api_padding_interface.h"

NAMESPACE_BEGIN(CryptoppApi)

// Implementation of a padding scheme that does nothing
class PaddingNoPadding : public PaddingInterface
{
public:
    void pad(const size_t blockSize, const byte *input, const size_t inputLength, byte **output, size_t &outputLength);
    void unpad(const size_t blockSize, const byte *input, const size_t inputLength, byte **output, size_t &outputLength);
    bool canPad() {return false;}
    bool canUnpad() {return false;}
};

NAMESPACE_END

#endif /* API_CRYPTOPP_PADDING_NO_PADDING_H */
