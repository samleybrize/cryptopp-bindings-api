
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_SYMMETRIC_KEY_ABSTRACT_H
#define API_CRYPTOPP_SYMMETRIC_KEY_ABSTRACT_H

#include "src/api_cryptopp.h"

NAMESPACE_BEGIN(CryptoppApi)

class SymmetricKeyAbstract
{
public:
    virtual ~SymmetricKeyAbstract() {delete[] m_key;}

    virtual bool isValidKeyLength(size_t length) const =0;
    virtual bool isValidKeyLength(size_t length, bool throwIfFalse) const;
    virtual void setKey(const byte *key, const size_t keyLength);
    virtual void getKey(byte *key);
    virtual size_t getKeyLength() {return m_keyLength;}

protected:
    SymmetricKeyAbstract()
        : m_key(NULL)
        , m_keyLength(0) {}
    bool hasValidKey(bool throwIfFalse);
    bool isKeyEqualsTo(SymmetricKeyAbstract *compare);

private:
    byte *m_key;
    size_t m_keyLength;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_KEY_ABSTRACT_H */
