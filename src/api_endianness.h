/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_ENDIANNESS_H
#define API_CRYPTOPP_ENDIANNESS_H

#include "api_cryptopp.h"

NAMESPACE_BEGIN(CryptoppApi)

enum Endianness {
    E_LITTLE_ENDIAN,
    E_BIG_ENDIAN
};

NAMESPACE_END

#endif /* API_CRYPTOPP_ENDIANNESS_H */
