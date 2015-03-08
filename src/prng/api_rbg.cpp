
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_rbg.h"

NAMESPACE_BEGIN(CryptoppApi)

void RandomByteGenerator::generate(byte *output, size_t size)
{
    if (size <= 0) {
        throw new Exception("Size must be a positive integer, 0 given");
    }

    m_rbg.GenerateBlock(output, size);
}

NAMESPACE_END
