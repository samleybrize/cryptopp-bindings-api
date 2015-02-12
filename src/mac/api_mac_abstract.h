
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

#include "api_cryptopp.h"
#include "api_mac_interface.h"

NAMESPACE_BEGIN(CryptoppApi)

class MacAbstract : public MacInterface
{
public:
    using SymmetricKeyAbstract::isValidKeyLength;
    const char *getName() const;
    size_t getDigestSize() const;
    size_t getBlockSize() const;
    bool isValidKeyLength(size_t length) const;
    void setKey(const byte *key, const size_t keyLength);
    void getKey(byte *key);
    size_t getKeyLength() {return m_keyLength;}
    void calculateDigest(byte *input, size_t inputLength, byte *output);
    void update(byte *input, size_t inputLength);
    void finalize(byte *output);
    void restart();

protected:
    MacAbstract();
    void setCryptoppObject(CryptoPP::MessageAuthenticationCode *mac);
    void setName(const std::string name);

private:
    char *m_name;
    CryptoPP::MessageAuthenticationCode *m_mac;
    byte *m_key;
    size_t m_keyLength;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_MAC_ABSTRACT_H */
