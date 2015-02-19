cmake_minimum_required(VERSION 2.8)

project(cryptopp-bindings-api)

include_directories(.)

# add custom modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

# sets the C++ version to C++0x
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")

# add crypto++ library
find_package(Crypto++ REQUIRED)
include_directories(${CRYPTO++_INCLUDE_DIR})

# adds the src directory
add_subdirectory(src build/lib)

# adds unit tests
add_subdirectory(tests build/tests EXCLUDE_FROM_ALL)
