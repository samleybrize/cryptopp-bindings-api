enable_testing()

add_executable(
    cryptopp-bindings-api-tests
    test_api_assertions.cpp

    utils/test_api_hex_utils.cpp

    padding/test_api_padding_no_padding.cpp
    padding/test_api_padding_pkcs7.cpp

    prng/test_api_rbg.cpp

    hash/test_api_hash_md5.cpp
    hash/test_api_hash_sha1.cpp
    hash/test_api_hash_sha3_224.cpp
    hash/test_api_hash_sha3_256.cpp
    hash/test_api_hash_sha3_384.cpp
    hash/test_api_hash_sha3_512.cpp

    mac/test_api_mac_cmac.cpp
    mac/test_api_mac_hmac.cpp
    mac/test_api_mac_ttmac.cpp

    symmetric/cipher/authenticated/test_api_authenticated_symmetric_cipher_ccm.cpp
    symmetric/cipher/authenticated/test_api_authenticated_symmetric_cipher_eax.cpp
    symmetric/cipher/authenticated/test_api_authenticated_symmetric_cipher_gcm.cpp
    symmetric/cipher/authenticated/test_api_authenticated_symmetric_cipher_generic.cpp

    symmetric/cipher/block/test_api_block_cipher_aes.cpp

    symmetric/cipher/stream/test_api_stream_cipher_panama.cpp
    symmetric/cipher/stream/test_api_stream_cipher_salsa20.cpp
    symmetric/cipher/stream/test_api_stream_cipher_sosemanuk.cpp
    symmetric/cipher/stream/test_api_stream_cipher_xsalsa20.cpp

    symmetric/mode/test_api_symmetric_mode_ecb.cpp
    symmetric/mode/test_api_symmetric_mode_cbc.cpp
    symmetric/mode/test_api_symmetric_mode_cfb.cpp
    symmetric/mode/test_api_symmetric_mode_ofb.cpp
    symmetric/mode/test_api_symmetric_mode_ctr.cpp
)

target_link_libraries(cryptopp-bindings-api-tests cryptopp-bindings-api)

add_test(cryptopp-bindings-api-tests cryptopp-bindings-api-tests)

add_custom_target(check cryptopp-bindings-api-tests)
add_dependencies(check cryptopp-bindings-api-tests)

# add Google Test library
add_subdirectory(lib/gtest-1.7.0)
include_directories(${gtest_SOURCE_DIR}/include ${gtest_INCLUDE_DIRS})
target_link_libraries(cryptopp-bindings-api-tests gtest_main)
