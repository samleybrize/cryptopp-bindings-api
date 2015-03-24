
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

class HashTransformationInterface
{
public:
    virtual ~HashTransformationInterface() {}

    virtual const char *getName() const =0;
    virtual size_t getDigestSize() const =0;
    virtual size_t getBlockSize() const =0;
    virtual void calculateDigest(const byte *input, size_t inputLength, byte *output) =0;
    virtual void update(const byte *input, size_t inputLength) =0;
    virtual void finalize(byte *output) =0;
    virtual void restart() =0;

    virtual CryptoPP::HashTransformation *getCryptoppObject() =0;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_HASH_TRANSFORMATION_INTERFACE_H */
