
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

// Abstract class that implements symmetric key related tasks
class SymmetricKeyAbstract
{
public:
    virtual ~SymmetricKeyAbstract() {delete[] m_key;}

    // indicates if a given length can be a valid key
    virtual bool isValidKeyLength(size_t length) const =0;

    // indicates if a given length can be a valid key
    // the 'throwIfFalse' argument indicates if an exception should be thrown in case the length is not a valid key length
    virtual bool isValidKeyLength(size_t length, bool throwIfFalse) const;

    // sets the key
    virtual void setKey(const byte *key, const size_t keyLength);

    // returns the key
    // the key size is the one provided by getKeyLength()
    virtual void getKey(byte *key);

    // returns the key length
    virtual size_t getKeyLength() {return m_keyLength;}

    // indicates if a valid key has been setted
    // the 'throwIfFalse' argument indicates if an exception should be thrown in case the method return false
    virtual bool hasValidKey(bool throwIfFalse);

protected:
    SymmetricKeyAbstract()
        : m_key(NULL)
        , m_keyLength(0) {}

    // indicates if another instance of SymmetricKeyAbstract hold a key identical to the one owned by this instance
    bool isKeyEqualsTo(SymmetricKeyAbstract *compare);

private:
    byte *m_key;
    size_t m_keyLength;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_KEY_ABSTRACT_H */
