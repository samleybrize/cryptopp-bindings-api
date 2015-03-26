
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_PADDING_INTERFACE_H
#define API_CRYPTOPP_PADDING_INTERFACE_H

#include "src/api_cryptopp.h"

NAMESPACE_BEGIN(CryptoppApi)

// Interface for classes that implements a padding scheme
class PaddingInterface
{
public:
    // TODO comment
    virtual ~PaddingInterface() {}
    virtual void pad(const size_t blockSize, const byte *input, const size_t inputLength, byte **output, size_t &outputLength) =0;
    virtual void unpad(const size_t blockSize, const byte *input, const size_t inputLength, byte **output, size_t &outputLength) =0;
    virtual bool canPad() =0;
    virtual bool canUnpad() =0;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_PADDING_INTERFACE_H */
