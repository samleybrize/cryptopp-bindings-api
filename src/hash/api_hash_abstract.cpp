
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_hash_abstract.h"

NAMESPACE_BEGIN(CryptoppApi)

HashAbstract::HashAbstract(CryptoPP::HashTransformation *hash, char *name)
    : m_hash(hash)
    , m_name(name)
{
}

const char *HashAbstract::getName() const
{
    return m_name;
}

size_t HashAbstract::getDigestSize() const
{
    return m_hash->DigestSize();
}

size_t HashAbstract::getBlockSize() const
{
    return m_hash->BlockSize();
}

void HashAbstract::calculateDigest(const byte *input, size_t inputLength, byte *output)
{
    m_hash->CalculateDigest(output, input, inputLength);
}

void HashAbstract::update(const byte *input, size_t inputLength)
{
    m_hash->Update(input, inputLength);
}

void HashAbstract::finalize(byte *output)
{
    m_hash->Final(output);
}

void HashAbstract::restart()
{
    m_hash->Restart();
}

NAMESPACE_END
