
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_MAC_ABSTRACT_H
#define API_CRYPTOPP_MAC_ABSTRACT_H

#include "src/api_cryptopp.h"
#include "api_mac_interface.h"
#include <string.h>

NAMESPACE_BEGIN(CryptoppApi)

// Abstract class for MAC classes that implements common tasks
class MacAbstract : public MacInterface
{
public:
    // TODO comments
    using SymmetricKeyAbstract::isValidKeyLength;

    const char *getName() const;
    size_t getDigestSize() const;
    size_t getBlockSize() const;
    bool isValidKeyLength(size_t length) const;
    void setKey(const byte *key, const size_t keyLength);
    void calculateDigest(const byte *input, size_t inputLength, byte *output);
    void update(const byte *input, size_t inputLength);
    void finalize(byte *output);
    void restart();

    CryptoPP::MessageAuthenticationCode *getCryptoppObject() {return m_mac;}

protected:
    // TODO comments
    MacAbstract();
    void setCryptoppObject(CryptoPP::MessageAuthenticationCode *mac);
    void setName(const std::string name);

private:
    // TODO comments
    std::string m_name;
    CryptoPP::MessageAuthenticationCode *m_mac;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_MAC_ABSTRACT_H */
