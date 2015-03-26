
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_HASH_INTERFACE_H
#define API_CRYPTOPP_HASH_INTERFACE_H

#include "src/api_cryptopp.h"
#include "api_hash_transformation_interface.h"

NAMESPACE_BEGIN(CryptoppApi)

// Interface for Hash classes
class HashInterface : public HashTransformationInterface
{
};

NAMESPACE_END

#endif /* API_CRYPTOPP_HASH_INTERFACE_H */
