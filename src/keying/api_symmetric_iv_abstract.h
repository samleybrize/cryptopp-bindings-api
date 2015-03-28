
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_SYMMETRIC_IV_ABSTRACT_H
#define API_CRYPTOPP_SYMMETRIC_IV_ABSTRACT_H

#include "src/api_cryptopp.h"

NAMESPACE_BEGIN(CryptoppApi)

// Abstract class that implements IV related tasks
class SymmetricIvAbstract
{
public:
    virtual ~SymmetricIvAbstract() {delete[] m_iv;}

    // indicates if a given length can be a valid IV
    virtual bool isValidIvLength(size_t length) const =0;

    // indicates if a given length can be a valid IV
    // the 'throwIfFalse' argument indicates if an exception should be thrown in case the length is not a valid IV length
    virtual bool isValidIvLength(size_t length, bool throwIfFalse) const;

    // sets the IV
    virtual void setIv(const byte *iv, const size_t ivLength);

    // returns the IV
    // the IV size is the one provided by getIvLength()
    virtual void getIv(byte *iv);

    // returns the IV length
    virtual size_t getIvLength() {return m_ivLength;}

    // indicates if a valid IV has been setted
    // the 'throwIfFalse' argument indicates if an exception should be thrown in case the method return false
    virtual bool hasValidIv(bool throwIfFalse);

protected:
    SymmetricIvAbstract()
        : m_iv(NULL)
        , m_ivLength(0) {}

private:
    byte *m_iv;
    size_t m_ivLength;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_IV_ABSTRACT_H */
