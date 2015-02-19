
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

class HexUtils
{
public:
    static void bin2hex(const byte *input, const size_t inputLength, char **output, size_t &outputLength);
    static void hex2bin(const char *input, const size_t inputLength, byte **output, size_t &outputLength);
};

NAMESPACE_END

#endif /* API_CRYPTOPP_HEX_UTILS_H */
