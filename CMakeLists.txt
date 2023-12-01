cmake_minimum_required(VERSION 3.11)

set(TARGET "tls_client")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(${TARGET})

add_executable(${TARGET})

target_include_directories(${TARGET} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/config
    ${CMAKE_CURRENT_SOURCE_DIR}/includes
)

target_sources(${TARGET} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/sources/tls_client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sources/wolfssl.c
)


include(WolfSSL.cmake)

