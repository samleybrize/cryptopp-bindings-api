
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_HEX_UTILS_H
#define API_CRYPTOPP_HEX_UTILS_H

#include "src/api_cryptopp.h"

NAMESPACE_BEGIN(CryptoppApi)

// Utility class that take care of hex encoding/decoding
class HexUtils
{
public:
    // convert binary data into hexadecimal representation
    // the 'output' argument is allocated in the method and should be freed
    // the 'outputLength' argument will be filled with the allocated output size
    static void bin2hex(const byte *input, const size_t inputLength, char **output, size_t &outputLength);

    // decodes a hexadecimally encoded binary string
    // the 'output' argument is allocated in the method and should be freed
    // the 'outputLength' argument will be filled with the allocated output size
    static void hex2bin(const char *input, const size_t inputLength, byte **output, size_t &outputLength);
};

NAMESPACE_END

#endif /* API_CRYPTOPP_HEX_UTILS_H */
