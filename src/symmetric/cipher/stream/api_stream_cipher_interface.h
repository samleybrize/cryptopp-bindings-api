
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_STREAM_CIPHER_INTERFACE_H
#define API_CRYPTOPP_STREAM_CIPHER_INTERFACE_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/api_symmetric_transformation_interface.h"

NAMESPACE_BEGIN(CryptoppApi)

class StreamCipherInterface : public SymmetricTransformationInterface
{
public:
    virtual ~StreamCipherInterface() {}
};

NAMESPACE_END

#endif /* API_CRYPTOPP_STREAM_CIPHER_INTERFACE_H */
