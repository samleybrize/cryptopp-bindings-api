
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_SYMMETRIC_MODE_CBC_H
#define API_CRYPTOPP_SYMMETRIC_MODE_CBC_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/block/api_block_cipher_interface.h"
#include "api_symmetric_mode_abstract.h"
#include <modes.h>

NAMESPACE_BEGIN(CryptoppApi)

// CBC cipher mode of operation implementation
class SymmetricModeCbc : public SymmetricModeAbstract
{
public:
    // TODO comments
    SymmetricModeCbc(BlockCipherInterface *cipher);
    ~SymmetricModeCbc();

private:
    // TODO comments
    CryptoPP::CBC_Mode_ExternalCipher::Encryption *m_encryptor;
    CryptoPP::CBC_Mode_ExternalCipher::Decryption *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_MODE_CBC_H */
