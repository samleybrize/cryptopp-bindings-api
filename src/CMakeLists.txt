# add sources
SET(CRYPTOPP_API_SRC
    keying/api_symmetric_iv_abstract.cpp
    keying/api_symmetric_key_abstract.cpp

    hash/api_hash_abstract.cpp
    hash/api_hash_md5.cpp
    hash/api_hash_sha1.cpp
    hash/api_hash_sha3.cpp

    mac/api_mac_abstract.cpp
    mac/api_mac_hmac.cpp
    mac/api_mac_ttmac.cpp

    symmetric/cipher/block/api_block_cipher_abstract.cpp
    symmetric/cipher/block/api_block_cipher_aes.cpp

    symmetric/cipher/stream/api_stream_cipher_abstract.cpp
    symmetric/cipher/stream/api_stream_cipher_panama.cpp
    symmetric/cipher/stream/api_stream_cipher_salsa20.cpp
    symmetric/cipher/stream/api_stream_cipher_sosemanuk.cpp
    symmetric/cipher/stream/api_stream_cipher_xsalsa20.cpp

    symmetric/cipher/authenticated/api_authenticated_symmetric_cipher_abstract.cpp
    symmetric/cipher/authenticated/api_authenticated_symmetric_cipher_ccm.cpp
    symmetric/cipher/authenticated/api_authenticated_symmetric_cipher_eax.cpp
    symmetric/cipher/authenticated/api_authenticated_symmetric_cipher_gcm.cpp

    symmetric/mode/api_symmetric_mode_abstract.cpp
    symmetric/mode/api_symmetric_mode_ecb.cpp
    symmetric/mode/api_symmetric_mode_cbc.cpp
    symmetric/mode/api_symmetric_mode_cfb.cpp
    symmetric/mode/api_symmetric_mode_ofb.cpp
    symmetric/mode/api_symmetric_mode_ctr.cpp

    padding/api_padding_no_padding.cpp
    padding/api_padding_pkcs7.cpp

    prng/api_rbg.cpp

    utils/api_hex_utils.cpp
)

add_library(
    cryptopp-bindings-api
    STATIC
    ${CRYPTOPP_API_SRC}
)

# link crypto++ library
target_link_libraries(cryptopp-bindings-api ${CRYPTO++_LIBRARIES})
