
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_RANDOM_BYTE_GENERATOR_INTERFACE_H
#define API_CRYPTOPP_RANDOM_BYTE_GENERATOR_INTERFACE_H

#include "src/api_cryptopp.h"

NAMESPACE_BEGIN(CryptoppApi)

// Interface for classes that implements a pseudo-random byte generator
class RandomByteGeneratorInterface
{
public:
    virtual ~RandomByteGeneratorInterface() {}

    // generates a random byte sequence
    virtual void generate(byte *output, size_t size) =0;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_RANDOM_BYTE_GENERATOR_INTERFACE_H */
