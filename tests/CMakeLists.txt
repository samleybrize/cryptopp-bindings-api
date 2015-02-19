enable_testing()

add_executable(
    cryptopp-bindings-api-tests
    test_api_assertions.cpp

    hash/test_api_hash_md5.cpp
    hash/test_api_hash_sha1.cpp
    hash/test_api_hash_sha3.cpp
)

target_link_libraries(cryptopp-bindings-api-tests cryptopp-bindings-api)

add_test(cryptopp-bindings-api-tests cryptopp-bindings-api-tests)

add_custom_target(check cryptopp-bindings-api-tests)
add_dependencies(check cryptopp-bindings-api-tests)

# add Google Test library
add_subdirectory(lib/gtest-1.7.0)
include_directories(${gtest_SOURCE_DIR}/include ${gtest_INCLUDE_DIRS})
target_link_libraries(cryptopp-bindings-api-tests gtest_main)
