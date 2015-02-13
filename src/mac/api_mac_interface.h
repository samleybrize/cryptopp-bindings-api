
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_MAC_INTERFACE_H
#define API_CRYPTOPP_MAC_INTERFACE_H

#include "src/api_cryptopp.h"
#include "src/hash/api_hash_transformation_interface.h"
#include "src/keying/api_symmetric_key_abstract.h"

NAMESPACE_BEGIN(CryptoppApi)

class MacInterface : public HashTransformationInterface, public SymmetricKeyAbstract
{
};

NAMESPACE_END

#endif /* API_CRYPTOPP_MAC_INTERFACE_H */
