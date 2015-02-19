/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_hex_utils.h"

NAMESPACE_BEGIN(CryptoppApi)

static char hexconvtab[] = "0123456789abcdef";

void HexUtils::bin2hex(const byte *input, const size_t inputLength, char **output, size_t &outputLength)
{
    size_t i;
    size_t j;
    outputLength    = 2 * inputLength;
    char *output2   = new char[outputLength];

    for (i = j = 0; i < inputLength; i++) {
        output2[j++] = hexconvtab[input[i] >> 4];
        output2[j++] = hexconvtab[input[i] & 15];
    }

    *output = output2;
}

void HexUtils::hex2bin(const char *input, const size_t inputLength, byte **output, size_t &outputLength)
{
    size_t targetLength = inputLength >> 1;
    outputLength        = 0;

    const byte *input2  = reinterpret_cast<const byte*>(input);
    byte *output2       = new byte[targetLength];
    size_t i;
    size_t j;

    for (i = j = 0; i < targetLength; i++) {
        byte c = input2[j++];

        if (c >= '0' && c <= '9') {
            output2[i] = (c - '0') << 4;
        } else if (c >= 'a' && c <= 'f') {
            output2[i] = (c - 'a' + 10) << 4;
        } else if (c >= 'A' && c <= 'F') {
            output2[i] = (c - 'A' + 10) << 4;
        } else {
            delete[] output2;
            return;
        }

        c = input2[j++];

        if (c >= '0' && c <= '9') {
            output2[i] |= c - '0';
        } else if (c >= 'a' && c <= 'f') {
            output2[i] |= c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            output2[i] |= c - 'A' + 10;
        } else {
            delete[] output2;
            return;
        }
    }

    outputLength    = targetLength;
    *output         = output2;
}

NAMESPACE_END
