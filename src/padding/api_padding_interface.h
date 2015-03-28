
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
    virtual ~PaddingInterface() {}

    // pads data
    // the 'blockSize' argument should be, for example, the block size of the cipher
    // the 'output' argument is allocated in the method and should be freed
    // the 'outputLength' argument will be filled with the allocated output size
    virtual void pad(const size_t blockSize, const byte *input, const size_t inputLength, byte **output, size_t &outputLength) =0;

    // unpads data
    // the 'blockSize' argument should be, for example, the block size of the cipher
    // the 'output' argument is allocated in the method and should be freed
    // the 'outputLength' argument will be filled with the allocated output size
    virtual void unpad(const size_t blockSize, const byte *input, const size_t inputLength, byte **output, size_t &outputLength) =0;

    // indicates if this padding scheme can pad data
    virtual bool canPad() =0;

    // indicates if this padding scheme can unpad data
    virtual bool canUnpad() =0;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_PADDING_INTERFACE_H */
