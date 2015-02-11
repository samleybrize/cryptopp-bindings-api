
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_hash_sha1.h"

NAMESPACE_BEGIN(CryptoppApi)

HashSha1::HashSha1()
    : HashAbstract(&m_hash, "sha1")
{
}

NAMESPACE_END
