cmake_minimum_required (VERSION 2.8)
project (CRYPTOGRAPHIC_LIB)

set (crypto_VERSION_MAJOR 1)
set (crypto_VERSION_MINOR 0)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)

if(CMAKE_BUILD_TYPE MATCHES "Debug" OR CMAKE_BUILD_TYPE MATCHES "Release")
    message(STATUS "CMake build type: ${CMAKE_BUILD_TYPE}")
else()
    message(FATAL_ERROR "CMake build type \"${CMAKE_BUILD_TYPE}\" is not supported")
endif()

message(STATUS "CMAKE_SOURCE_DIR: " ${CMAKE_SOURCE_DIR})

find_program (CONANBIN conan)
if(CONANBIN)
    message (STATUS "conan C++ package manager: installed")
    find_file (CONANFILE "${CMAKE_SOURCE_DIR}/conanfile.txt")
    if (CONANFILE)
        message (STATUS "conanfile.txt: found")
    endif()
endif()

if (EXISTS "${CMAKE_BINARY_DIR}/conanbuildinfo.cmake")
    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    conan_basic_setup()
else()
    include (CheckIncludeFileCXX)
    CHECK_INCLUDE_FILE_CXX ("gsl/span" HAVE_GSL_SPAN)
    if(NOT HAVE_GSL_SPAN)
        message(FATAL_ERROR "gsl library: <gsl/span> not found")
    endif()
endif()

include (CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG(-std=c++14 COMPILER_SUPPORTS_CXX14)
if(COMPILER_SUPPORTS_CXX14)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
else()
    message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++14 support.
Please use a different C++ compiler.")
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
    #set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W -Wall -Werror -Wextra")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-undefined")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W -Wall -Wextra")
    set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -O0 -fno-omit-frame-pointer -DDEBUG")
    set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -DNDEBUG")
endif(CMAKE_COMPILER_IS_GNUCXX)

add_subdirectory (src)
add_subdirectory (test)

