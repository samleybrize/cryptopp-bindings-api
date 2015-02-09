
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
#include <string>

NAMESPACE_BEGIN(CryptoppApi)

class Exception
{
public:
    Exception(const std::string message)
        : Exception(message, 0) {}
    Exception(const std::string message, const int code)
        : m_msg(message)
        , m_code(code) {}

    std::string getMessage() {return m_msg;}
    int getCode() {return m_code;}

protected:
    std::string m_msg;
    int m_code;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_EXCEPTION_H */
