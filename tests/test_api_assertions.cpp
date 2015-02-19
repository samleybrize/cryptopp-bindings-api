/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "test_api_assertions.h"
#include <ostream>
#include <string>

static char hexconvtab[] = "0123456789abcdef";

static std::string bin2hex(const byte *binary, const size_t binarySize) {
    size_t i;
    size_t j;
    size_t hexSize  = 2 * binarySize;
    byte *result    = new byte[hexSize];

    for (i = j = 0; i < binarySize; i++) {
        result[j++] = hexconvtab[binary[i] >> 4];
        result[j++] = hexconvtab[binary[i] & 15];
    }

    std::string hex(reinterpret_cast<char*>(result), hexSize);
    delete[] result;
    return hex;
}

void hex2bin(const char *input, size_t inputLength, byte **output, size_t &outputLength) {
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

static std::string byteArrayEqualsFailure(byte *expected, size_t expectedSize, byte *actual, size_t actualSize) {
    // convert to hex
    std::string hexExpected = bin2hex(expected, expectedSize);
    std::string hexActual   = bin2hex(actual, actualSize);

    // build message
    std::stringstream msg;
    msg << "  Actual  : (" << actualSize << ") " << hexActual;
    msg << "\n  Expected: (" << expectedSize << ") " << hexExpected;

    return msg.str();
}

::testing::AssertionResult ByteArrayEquals(byte *expected, size_t expectedSize, byte *actual, size_t actualSize) {
    if (expectedSize != actualSize) {
        std::string msg = byteArrayEqualsFailure(expected, expectedSize, actual, actualSize);
        return ::testing::AssertionFailure() << msg;
    }

    for (size_t i(0); i < expectedSize; ++i){
        if (expected[i] != actual[i]){
            std::string msg = byteArrayEqualsFailure(expected, expectedSize, actual, actualSize);
            return ::testing::AssertionFailure() << msg;
        }
    }

    return ::testing::AssertionSuccess();
}
