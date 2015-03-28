
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_SYMMETRIC_MODE_CTR_H
#define API_CRYPTOPP_SYMMETRIC_MODE_CTR_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/block/api_block_cipher_interface.h"
#include "api_symmetric_mode_abstract.h"
#include <modes.h>

NAMESPACE_BEGIN(CryptoppApi)

// CTR cipher mode of operation implementation
class SymmetricModeCtr : public SymmetricModeAbstract
{
public:
    SymmetricModeCtr(BlockCipherInterface *cipher);
    ~SymmetricModeCtr();

private:
    CryptoPP::CTR_Mode_ExternalCipher::Encryption *m_encryptor;
    CryptoPP::CTR_Mode_ExternalCipher::Decryption *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_MODE_CTR_H */
