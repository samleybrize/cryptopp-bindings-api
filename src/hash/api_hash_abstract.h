
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_HASH_ABSTRACT_H
#define API_CRYPTOPP_HASH_ABSTRACT_H

#include "src/api_cryptopp.h"
#include "api_hash_interface.h"
#include <string.h>

NAMESPACE_BEGIN(CryptoppApi)

class HashAbstract : public HashInterface
{
public:
    const char *getName() const;
    size_t getDigestSize() const;
    size_t getBlockSize() const;
    void calculateDigest(const byte *input, size_t inputLength, byte *output);
    void update(const byte *input, size_t inputLength);
    void finalize(byte *output);
    void restart();

    CryptoPP::HashTransformation *getCryptoppObject() {return m_hash;}

protected:
    HashAbstract(CryptoPP::HashTransformation *hash, const std::string name);

private:
    std::string m_name;
    CryptoPP::HashTransformation *m_hash;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_HASH_ABSTRACT_H */
