
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_SYMMETRIC_MODE_CFB_H
#define API_CRYPTOPP_SYMMETRIC_MODE_CFB_H

#include "src/api_cryptopp.h"
#include "src/symmetric/cipher/block/api_block_cipher_interface.h"
#include "api_symmetric_mode_abstract.h"
#include <modes.h>

NAMESPACE_BEGIN(CryptoppApi)

class CryptoppCfb : public CryptoPP::CFB_Mode_ExternalCipher::Encryption
{
public:
    CryptoppCfb();
    void SetCipher(CryptoPP::BlockCipher &cipher);
};

class SymmetricModeCfb : public SymmetricModeAbstract
{
public:
    SymmetricModeCfb(BlockCipherInterface *cipher);
    ~SymmetricModeCfb();

private:
    CryptoppCfb *m_encryptor;
    CryptoppCfb *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_MODE_CFB_H */
