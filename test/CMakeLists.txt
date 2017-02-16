cmake_minimum_required (VERSION 2.8)
project (test-crypto)

find_package (GTest REQUIRED)
include_directories (${GTEST_INCLUDE_DIRS})

set(THREADS_PREFER_PTHREAD_FLAG on)
find_package (Threads REQUIRED)

include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/../include")

find_library (CRYPTO_LIBRARY
    NAMES crypto #crypto_static
    HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../src"
    )

link_directories("${CMAKE_CURRENT_BINARY_DIR}/../src")

set (SRC_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/test_libcrypto.cpp"
    )

add_executable (test-crypto ${SRC_FILES})
target_link_libraries (test-crypto
    pthread
    ${GTEST_BOTH_LIBRARIES}
    #crypto_static
    crypto
    )

include (CTest)
add_test (unit_tests "${CMAKE_CURRENT_BINARY_DIR}/test-crypto")
