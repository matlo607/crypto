cmake_minimum_required (VERSION 2.8)
project (test-crypto)

if (NOT EXISTS "${CMAKE_BINARY_DIR}/conanbuildinfo.cmake")
    find_package (GTest REQUIRED)
    include_directories (${GTEST_INCLUDE_DIRS})
endif()

set(THREADS_PREFER_PTHREAD_FLAG on)
find_package (Threads REQUIRED)

include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/../include")

find_library (CRYPTO_LIBRARY
    NAMES cryptonew #cryptonew_static
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
    #cryptonew_static
    cryptonew
    ${CONAN_LIBS}
    )

include (CTest)
add_test (unit_tests "${CMAKE_CURRENT_BINARY_DIR}/test-crypto")
