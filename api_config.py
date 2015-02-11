def getSourceFileList(cryptoppVersion):
    sourceFileList = []
    sourceFileList.append("src/keying/api_symmetric_iv_abstract.cpp")
    sourceFileList.append("src/keying/api_symmetric_key_abstract.cpp")

    sourceFileList.append("src/symmetric/cipher/block/api_block_cipher_abstract.cpp")
    sourceFileList.append("src/symmetric/cipher/block/api_block_cipher_aes.cpp")

    sourceFileList.append("src/symmetric/cipher/stream/api_stream_cipher_abstract.cpp")
    sourceFileList.append("src/symmetric/cipher/stream/api_stream_cipher_panama.cpp")
    sourceFileList.append("src/symmetric/cipher/stream/api_stream_cipher_salsa20.cpp")
    sourceFileList.append("src/symmetric/cipher/stream/api_stream_cipher_sosemanuk.cpp")
    sourceFileList.append("src/symmetric/cipher/stream/api_stream_cipher_xsalsa20.cpp")

    return sourceFileList
