# Crypto++ bindings API

Provides an object-oriented API to use a wide variety of cryptographic algorithms based on the Crypto++ library.
The API is not strictly identical to the original Crypto++ API and has been simplified to be usable by anyone that has not any knowledge in cryptography.

[![Build Status](https://travis-ci.org/samleybrize/cryptopp-bindings-api.svg?branch=master)](https://travis-ci.org/samleybrize/cryptopp-bindings-api)

## Requirements

- Crypto++ library 5.6.1+
- CMake 2.8+

The Crypto++ library can be installed with one of the following commands, depending on your distribution:
- Ubuntu: `sudo apt-get install libcrypto++-dev`
- Debian: `sudo apt-get install libcrypto++-dev`
- ArchLinux: `sudo pacman -S crypto++`
- CentOS/RedHat: `yum install cryptopp-devel`

## Installation

```sh
cmake .
make
```

Build only as a static library that is located at `build/lib/libcryptopp-bindings-api.a`

Unit tests can be runned with `make check`.

## Status

Available
- Symmetric encryption
- Hash functions
- MAC algorithms

Comming
- Asymmetric cryptography
- Key derivation functions

## Author

This project is authored and maintained by Stephen Berquet.

## License

Licensed under the MIT License - see the [LICENSE](LICENSE) file for details
