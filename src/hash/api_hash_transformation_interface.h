
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_HASH_TRANSFORMATION_INTERFACE_H
#define API_CRYPTOPP_HASH_TRANSFORMATION_INTERFACE_H

#include "src/api_cryptopp.h"

NAMESPACE_BEGIN(CryptoppApi)

// Interface for classes that performs a hash transformation
class HashTransformationInterface
{
public:
    virtual ~HashTransformationInterface() {}

    // return algorithm name
    virtual const char *getName() const =0;

    // returns digest size (in bytes)
    virtual size_t getDigestSize() const =0;

    // returns block size (in bytes)
    virtual size_t getBlockSize() const =0;

    // calculate the digest of a given input
    // output size is equal to the digest size
    virtual void calculateDigest(const byte *input, size_t inputLength, byte *output) =0;

    // adds data to current incremental digest calculation
    virtual void update(const byte *input, size_t inputLength) =0;

    // finalize current incremental digest calculation
    // output size is equal to the digest size
    virtual void finalize(byte *output) =0;

    // resets current incremental digest calculation
    virtual void restart() =0;

    // returns the Crypto++ object used
    virtual CryptoPP::HashTransformation *getCryptoppObject() =0;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_HASH_TRANSFORMATION_INTERFACE_H */
