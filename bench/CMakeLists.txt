cmake_minimum_required (VERSION 2.8)
project (bench-crypto)

if (NOT EXISTS "${CMAKE_BINARY_DIR}/conanbuildinfo.cmake")
    find_package(OpenSSL REQUIRED)
    message ("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message ("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
    include_directories (${OPENSSL_INCLUDE_DIR})
endif()

include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/../include")

find_library (CRYPTO_LIBRARY
    NAMES cryptonew_static
    HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../src"
    )

link_directories("${CMAKE_CURRENT_BINARY_DIR}/../src")

set (SRC_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/bench_libcrypto.cpp"
    )

add_executable (bench-crypto ${SRC_FILES})
target_link_libraries (bench-crypto
    ${OPENSSL_LIBRARIES}
    cryptonew_static
    ${CONAN_LIBS}
    )

include (CTest)
add_test (bench_tests "${CMAKE_CURRENT_BINARY_DIR}/bench-crypto")
