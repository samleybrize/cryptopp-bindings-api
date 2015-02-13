
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_rbg.h"

NAMESPACE_BEGIN(CryptoppApi)

void RandomByteGenerator::generate(byte *output, size_t size)
{
    m_rbg.GenerateBlock(output, size);
}

NAMESPACE_END