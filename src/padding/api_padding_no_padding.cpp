
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_padding_no_padding.h"

NAMESPACE_BEGIN(CryptoppApi)

void PaddingNoPadding::pad(size_t blockSize, byte *input, size_t inputLength, byte **output, size_t &outputLength)
{
    outputLength    = inputLength;
    *output         = new byte[inputLength];
    memcpy(*output, input, inputLength);
}

void PaddingNoPadding::unpad(size_t blockSize, byte *input, size_t inputLength, byte **output, size_t &outputLength)
{
    outputLength    = inputLength;
    *output         = new byte[inputLength];
    memcpy(*output, input, inputLength);
}

NAMESPACE_END
