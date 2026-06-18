cmake_minimum_required(VERSION 3.10)
project(apksign CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(APKSIG_USE_OPENSSL "Build apksig_v2_verify against OpenSSL instead of mbedTLS" OFF)

if(APKSIG_USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
else()
    find_library(MBEDTLS_LIBRARY mbedtls REQUIRED)
    find_library(MBEDX509_LIBRARY mbedx509 REQUIRED)
    find_library(MBEDCRYPTO_LIBRARY mbedcrypto REQUIRED)
endif()

add_executable(apksig_v2_verify
    apksig_v2_verify.cpp
)

target_compile_options(apksig_v2_verify PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
)

if(APKSIG_USE_OPENSSL)
    target_compile_definitions(apksig_v2_verify PRIVATE APKSIG_USE_OPENSSL)
    target_link_libraries(apksig_v2_verify PRIVATE
        OpenSSL::Crypto
    )
else()
    target_link_libraries(apksig_v2_verify PRIVATE
        ${MBEDTLS_LIBRARY}
        ${MBEDX509_LIBRARY}
        ${MBEDCRYPTO_LIBRARY}
    )
endif()

install(TARGETS apksig_v2_verify
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
