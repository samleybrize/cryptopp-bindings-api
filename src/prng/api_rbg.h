
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_RANDOM_BYTE_GENERATOR_H
#define API_CRYPTOPP_RANDOM_BYTE_GENERATOR_H

#include "src/api_cryptopp.h"
#include "api_rbg_interface.h"
#include <osrng.h>

NAMESPACE_BEGIN(CryptoppApi)

// Implementation of a pseudo-random byte generator
class RandomByteGenerator : public RandomByteGeneratorInterface
{
public:
    void generate(byte *output, size_t size);

private:
    CryptoPP::AutoSeededRandomPool m_rbg;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_RANDOM_BYTE_GENERATOR_H */
