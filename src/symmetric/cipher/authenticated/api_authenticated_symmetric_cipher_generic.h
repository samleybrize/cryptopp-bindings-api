
/*
 * This file is part of cryptopp-bindings-api.
 *
 * (c) Stephen Berquet <stephen.berquet@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

#ifndef API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_GENERIC_H
#define API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_GENERIC_H

#include "src/api_cryptopp.h"
#include "src/mac/api_mac_interface.h"
#include "src/symmetric/cipher/api_symmetric_transformation_interface.h"
#include "src/symmetric/cipher/stream/api_stream_cipher_interface.h"
#include "src/symmetric/mode/api_symmetric_mode_interface.h"
#include "api_authenticated_symmetric_cipher_abstract.h"

NAMESPACE_BEGIN(CryptoppApi)

// internal namespace
NAMESPACE_BEGIN(CryptoppApiInternal)

// AuthenticatedSymmetricCipher that take an instance of CryptoPP::SymmetricCipher and an instance of CryptoPP::MessageAuthenticationCode
class CryptoppAuthenticatedSymmetricCipherGeneric
{
public:
    // base class
    class Base : public CryptoPP::AuthenticatedSymmetricCipher
    {
    public:
        void ProcessData(byte *outString, const byte *inString, size_t length);

        std::string AlgorithmName() const {return "generic";}

        unsigned int MandatoryBlockSize() const {return m_cipher->MandatoryBlockSize();}
        unsigned int OptimalBlockSize() const  {return m_cipher->OptimalBlockSize();}
        unsigned int MinLastBlockSize() const {return m_cipher->MinLastBlockSize();}
        unsigned int GetOptimalBlockSizeUsed() const {return m_cipher->GetOptimalBlockSizeUsed();}
        unsigned int OptimalDataAlignment() const {return m_cipher->OptimalDataAlignment();}
        void ProcessLastBlock(byte *outString, const byte *inString, size_t length) {m_cipher->ProcessLastBlock(outString, inString, length);}
        bool IsRandomAccess() const {return m_cipher->IsRandomAccess();}
        void Seek(CryptoPP::lword n) {m_cipher->Seek(n);}
        bool IsSelfInverting() const {return m_cipher->IsSelfInverting();}
        size_t MinKeyLength() const {return m_cipher->MinKeyLength();}
        size_t MaxKeyLength() const {return m_cipher->MaxKeyLength();}
        size_t DefaultKeyLength() const {return m_cipher->DefaultKeyLength();}
        size_t GetValidKeyLength(size_t n) const {return m_cipher->GetValidKeyLength(n);}
        unsigned int IVSize() const {return m_cipher->IVSize();}
        unsigned int MinIVLength() const {return m_cipher->MinIVLength();}
        unsigned int MaxIVLength() const {return m_cipher->MaxIVLength();}
        IV_Requirement IVRequirement() const {return m_cipher->IVRequirement();}
        void GetNextIV(CryptoPP::RandomNumberGenerator &rng, byte *IV) {m_cipher->GetNextIV(rng, IV);}

        unsigned int DigestSize() const {return m_mac->DigestSize();}
        void Update(const byte *input, size_t length) {m_mac->Update(input, length);}
        void Final(byte *digest) {TruncatedFinal(digest, DigestSize());}
        void TruncatedFinal(byte *digest, size_t digestSize) {m_mac->TruncatedFinal(digest, digestSize);}
        void CalculateDigest(byte *digest, const byte *input, size_t length) {Update(input, length); Final(digest);}
        bool Verify(const byte *digest) {return TruncatedVerify(digest, DigestSize());}
        bool VerifyDigest(const byte *digest, const byte *input, size_t length) {Update(input, length); return Verify(digest);}
        void CalculateTruncatedDigest(byte *digest, size_t digestSize, const byte *input, size_t length) {Update(input, length); TruncatedFinal(digest, digestSize);}
        bool VerifyTruncatedDigest(const byte *digest, size_t digestLength, const byte *input, size_t length) {Update(input, length); return TruncatedVerify(digest, digestLength);}
        byte * CreateUpdateSpace(size_t &size) {return m_mac->CreateUpdateSpace(size);}

        // unused
        CryptoPP::lword MaxHeaderLength() const {return 0;}
        CryptoPP::lword MaxMessageLength() const {return 0;}
        CryptoPP::lword MaxFooterLength() const {return 0;}
        bool NeedsPrespecifiedDataLengths() const {return false;}
        void EncryptAndAuthenticate(byte *ciphertext, byte *mac, size_t macSize, const byte *iv, int ivLength, const byte *header, size_t headerLength, const byte *message, size_t messageLength) {}
        bool DecryptAndVerify(byte *message, const byte *mac, size_t macLength, const byte *iv, int ivLength, const byte *header, size_t headerLength, const byte *ciphertext, size_t ciphertextLength) {return true;}

    protected:
        Base(CryptoPP::SymmetricCipher *cipher, CryptoPP::MessageAuthenticationCode *mac);

        // unused
        const Algorithm & GetAlgorithm() const {return *static_cast<const CryptoPP::MessageAuthenticationCode *>(this);}
        void UncheckedSpecifyDataLengths(CryptoPP::lword headerLength, CryptoPP::lword messageLength, CryptoPP::lword footerLength) {}
        void UncheckedSetKey(const byte *key, unsigned int length, const CryptoPP::NameValuePairs &params) {}

        CryptoPP::SymmetricCipher *m_cipher;
        CryptoPP::MessageAuthenticationCode *m_mac;
    };

    // encryption class
    class Encryption : public Base
    {
    public:
        Encryption(CryptoPP::SymmetricCipher *cipher, CryptoPP::MessageAuthenticationCode *mac);
        bool IsForwardTransformation() const {return true;}
    };

    // decryption class
    class Decryption : public Base
    {
    public:
        Decryption(CryptoPP::SymmetricCipher *cipher, CryptoPP::MessageAuthenticationCode *mac);
        bool IsForwardTransformation() const {return false;}
    };
};

NAMESPACE_END // CryptoppApiInternal

// Custom authenticated cipher mode scheme that work with a cipher and a MAC
class AuthenticatedSymmetricCipherGeneric : public AuthenticatedSymmetricCipherAbstract
{
public:
    AuthenticatedSymmetricCipherGeneric(SymmetricModeInterface *mode, MacInterface *mac);
    AuthenticatedSymmetricCipherGeneric(StreamCipherInterface *cipher, MacInterface *mac);
    ~AuthenticatedSymmetricCipherGeneric();

    size_t getBlockSize() const {return m_cipher->getBlockSize();}
    size_t getDigestSize() const {return m_mac->getDigestSize();}
    bool isValidKeyLength(size_t length) const {return m_cipher->isValidKeyLength(length);}
    bool isValidIvLength(size_t length) const {return m_cipher->isValidIvLength(length);}
    void getKey(byte *key) {m_cipher->getKey(key);}
    void getIv(byte *iv) {m_cipher->getIv(iv);}
    size_t getKeyLength() {return m_cipher->getKeyLength();}
    size_t getIvLength() {return m_cipher->getIvLength();}
    void setKey(const byte *key, const size_t keyLength) {m_cipher->setKey(key, keyLength);}
    void setIv(const byte *iv, const size_t ivLength) {m_cipher->setIv(iv, ivLength);}
    void restart();

    // proxy to the MAC's 'isValidKeyLength()' method
    bool isValidMacKeyLength(size_t length) const {return m_mac->isValidKeyLength(length);}

    // proxy to the MAC's 'isValidKeyLength(bool)' method
    bool isValidMacKeyLength(size_t length, bool throwIfFalse) const {return m_mac->isValidKeyLength(length, throwIfFalse);}

    // proxy to the MAC's 'getKey()' method
    void getMacKey(byte *key) {m_mac->getKey(key);}

    // proxy to the MAC's 'getKeyLength()' method
    size_t getMacKeyLength() {return m_mac->getKeyLength();}

    // proxy to the MAC's 'setKey()' method
    void setMacKey(const byte *key, const size_t keyLength) {m_mac->setKey(key, keyLength);}

protected:
    // proxy to the MAC's 'hasValidKey()' method
    bool hasValidMacKey(bool throwIfFalse);

    // call cipher's 'hasValidKey()' and MAC's 'hasValidKey()' methods
    bool hasValidKey(bool throwIfFalse);

private:
    SymmetricTransformationInterface *m_cipher;
    MacInterface *m_mac;
    CryptoppApiInternal::CryptoppAuthenticatedSymmetricCipherGeneric::Encryption *m_encryptor;
    CryptoppApiInternal::CryptoppAuthenticatedSymmetricCipherGeneric::Decryption *m_decryptor;
};

NAMESPACE_END

#endif /* API_CRYPTOPP_AUTHENTICATED_SYMMETRIC_CIPHER_GENERIC_H */
