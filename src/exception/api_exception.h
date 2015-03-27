
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_EXCEPTION_H
#define API_CRYPTOPP_EXCEPTION_H

#include "src/api_cryptopp.h"
#include <exception>
#include <string>

NAMESPACE_BEGIN(CryptoppApi)

class Exception : public std::exception
{
public:
    Exception(const std::string message)
        : m_msg(message)
        , m_code(0) {}
    Exception(const std::string message, const int code)
        : m_msg(message)
        , m_code(code) {}
    ~Exception() throw() {}

    std::string getMessage() {return m_msg;}
    int getCode() {return m_code;}
    virtual const char* what() const throw() {return m_msg.c_str();}

protected:
    std::string m_msg;
    int m_code;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_EXCEPTION_H */
