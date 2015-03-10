
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_padding_pkcs7.h"
#include <math.h>
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

void PaddingPkcs7::pad(const size_t blockSize, const byte *input, const size_t inputLength, byte **output, size_t &outputLength)
{
    size_t alignedSize = ceil(static_cast<double>(inputLength) / static_cast<double>(blockSize)) * blockSize;

    if (blockSize < 1) {
        std::stringstream msg;
        msg << "block size cannot be lower than 1, " << blockSize << " given";
        throw new Exception(msg.str());
    } else if (blockSize > 256) {
        // PKCS7 does not handle block sizes higher than 256
        throw new Exception("PKCS #7 padding does not handle block sizes higher than 256");
    } else if (alignedSize == inputLength) {
        // if input size is a multiple of block size, pad on an additional block size
        alignedSize += blockSize;
    }

    // pad
    outputLength    = alignedSize;
    const byte pad  = byte(outputLength - inputLength);
    *output         = new byte[outputLength];
    memcpy(*output, input, inputLength);
    memset(*output + inputLength, pad, outputLength - inputLength);
}

void PaddingPkcs7::unpad(const size_t blockSize, const byte *input, const size_t inputLength, byte **output, size_t &outputLength)
{
    if (blockSize < 1) {
        std::stringstream msg;
        msg << "block size cannot be lower than 1, " << blockSize << " given";
        throw new Exception(msg.str());
    } else if (blockSize > 256) {
        // PKCS7 does not handle block sizes higher than 256
        throw new Exception("PKCS #7 padding does not handle block sizes higher than 256");
    } else if (0 != inputLength % blockSize) {
        std::stringstream msg;
        msg << "data length is not a multiple of block size (block size is " << blockSize << ", data size is " << inputLength << ")";
        throw new Exception(msg.str());
    }

    // retrieve the pad character
    byte pad = input[inputLength - 1];

    if (pad < 1 || pad > blockSize || std::find_if(input + inputLength - pad, input + inputLength, std::bind2nd(std::not_equal_to<byte>(), pad)) != input + inputLength) {
        throw new Exception("invalid PKCS #7 block padding found");
    }

    // unpad
    outputLength    = inputLength - pad;
    *output         = new byte[outputLength];
    memcpy(output, input, outputLength);
}

NAMESPACE_END
