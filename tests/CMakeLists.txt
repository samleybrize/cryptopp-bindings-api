enable_testing()

add_executable(
    cryptopp-bindings-api-tests
    cryptopp-bindings-api-tests.cpp
)

target_link_libraries(cryptopp-bindings-api-tests cryptopp-bindings-api)

add_test(cryptopp-bindings-api-tests cryptopp-bindings-api-tests)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
add_dependencies(check cryptopp-bindings-api-tests)

# add Google Test library
add_subdirectory(lib/gtest-1.7.0)
include_directories(${gtest_SOURCE_DIR}/include ${gtest_INCLUDE_DIRS})
target_link_libraries(cryptopp-bindings-api-tests gtest_main)
