
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_hash_md5.h"

NAMESPACE_BEGIN(CryptoppApi)

HashMd5::HashMd5()
    : HashAbstract(&m_hash, "md5")
{
}

NAMESPACE_END
