
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_MAC_TTMAC_H
#define API_CRYPTOPP_MAC_TTMAC_H

#include "src/api_cryptopp.h"
#include "api_mac_abstract.h"
#include <ttmac.h>

NAMESPACE_BEGIN(CryptoppApi)

class MacTtmac : public MacAbstract
{
public:
    MacTtmac();

private:
    CryptoPP::TTMAC m_mac;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_MAC_TTMAC_H */
