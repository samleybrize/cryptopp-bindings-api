/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_H
#define API_CRYPTOPP_H

#define API_CRYPTOPP_VERSION 1000 /* 0.01.000 */
#define API_CRYPTOPP_VERSION_STR "0.1.0"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptlib.h>

#endif /* API_CRYPTOPP_H */
