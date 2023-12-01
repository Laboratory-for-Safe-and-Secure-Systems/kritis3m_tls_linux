cmake_minimum_required(VERSION 3.11)

set(TARGET kritis3m_tls)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(${TARGET})

add_executable(${TARGET})

target_include_directories(${TARGET} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/config
    ${CMAKE_CURRENT_SOURCE_DIR}/includes
)

target_sources(${TARGET} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/sources/main.c
)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/apps/tls_echo_server)

include(WolfSSL.cmake)

