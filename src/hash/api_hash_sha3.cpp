
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#if CRYPTOPP_VERSION >= 562

#include "api_hash_sha3.h"

NAMESPACE_BEGIN(CryptoppApi)

HashSha3_224::HashSha3_224()
    : HashAbstract(&m_hash, "sha3_224")
{
}

HashSha3_256::HashSha3_256()
    : HashAbstract(&m_hash, "sha3_256")
{
}

HashSha3_384::HashSha3_384()
    : HashAbstract(&m_hash, "sha3_384")
{
}

HashSha3_512::HashSha3_512()
    : HashAbstract(&m_hash, "sha3_512")
{
}

NAMESPACE_END

#endif /* CRYPTOPP_VERSION */
