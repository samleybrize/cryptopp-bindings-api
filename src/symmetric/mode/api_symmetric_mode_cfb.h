
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

// internal namespace
NAMESPACE_BEGIN(CryptoppApiInternal)

// Fork of the Crypto++ implementation of CFB (encryption part)
// Allow to instanciate without giving a key/IV (the original object cause a segfault in such case)
class CryptoppCfbEncryption : public CryptoPP::CFB_Mode_ExternalCipher::Encryption
{
public:
    CryptoppCfbEncryption(){}
    void SetCipher(CryptoPP::BlockCipher &cipher);
};

// Fork of the Crypto++ implementation of CFB (decryption part)
// Allow to instanciate without giving a key/IV (the original object cause a segfault in such case)
class CryptoppCfbDecryption : public CryptoPP::CFB_Mode_ExternalCipher::Decryption
{
public:
    CryptoppCfbDecryption(){}
    void SetCipher(CryptoPP::BlockCipher &cipher);
};

NAMESPACE_END // CryptoppApiInternal

// CFB cipher mode of operation implementation
class SymmetricModeCfb : public SymmetricModeAbstract
{
public:
    SymmetricModeCfb(BlockCipherInterface *cipher);
    ~SymmetricModeCfb();

private:
    CryptoppApiInternal::CryptoppCfbEncryption *m_encryptor;
    CryptoppApiInternal::CryptoppCfbDecryption *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_SYMMETRIC_MODE_CFB_H */
