
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#include "api_mac_ttmac.h"

NAMESPACE_BEGIN(CryptoppApi)

MacTtmac::MacTtmac()
    : MacAbstract()
{
    setName("two-track-mac");
    setCryptoppObject(&m_mac);
}

NAMESPACE_END
