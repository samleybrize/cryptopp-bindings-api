
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "src/exception/api_exception.h"
#include "api_mac_hmac.h"
#include <sstream>

NAMESPACE_BEGIN(CryptoppApi)

MacHmac::MacHmac(HashAbstract *hash)
    : MacAbstract()
{
    // name
    std::string name("hmac(");
    name.append(hash->getName());
    name.append(")");
    setName(name);

    // ensure that the hash algorithm is compatible
    if (0 == hash->getBlockSize()) {
        throw Exception("HMAC can only be used with a block-based hash function (block size > 0)");
    } else if (hash->getBlockSize() < hash->getDigestSize()) {
        std::stringstream msg;
        msg << "hash block size (" << hash->getBlockSize() << ") cannot be lower than digest size (" << hash->getDigestSize() << ")";
        throw Exception(msg.str());
    }

    // create mac object
    m_mac = new CryptoppHmac(hash->getCryptoppObject());
    setCryptoppObject(m_mac);

    // set an empty to avoid segfaults
    m_mac->SetKey(NULL, 0);
}

MacHmac::~MacHmac()
{
    delete m_mac;
}

NAMESPACE_END
