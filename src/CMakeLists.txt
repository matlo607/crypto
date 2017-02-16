cmake_minimum_required (VERSION 2.8)
project (crypto-all)

include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/../include")

set (SRC_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/MD4.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/MD5.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/SHA1.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/SHA224.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/SHA256.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/SHA384.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/SHA512.cpp"
    )

add_library (crypto_static STATIC ${SRC_FILES})
add_library (crypto SHARED ${SRC_FILES})

