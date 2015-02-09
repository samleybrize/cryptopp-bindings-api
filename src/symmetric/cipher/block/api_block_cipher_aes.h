
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_BLOCK_CIPHER_AES_H
#define API_CRYPTOPP_BLOCK_CIPHER_AES_H

#include "src/api_cryptopp.h"
#include "api_block_cipher_abstract.h"
#include <aes.h>

NAMESPACE_BEGIN(CryptoppApi)

class BlockCipherAes : public BlockCipherAbstract
{
public:
    BlockCipherAes();

private:
    CryptoPP::AES::Encryption m_encryptor;
    CryptoPP::AES::Decryption m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_BLOCK_CIPHER_AES_H */
