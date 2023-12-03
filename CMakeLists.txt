cmake_minimum_required(VERSION 3.24)

set(TARGET kritis3m_tls)

# Make sure VSCode and IntelliSense finds its necessary data
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(${TARGET})

# Define the main executable
add_executable(${TARGET})

# Include directories
target_include_directories(${TARGET} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/config
    ${CMAKE_CURRENT_SOURCE_DIR}/includes
)

# Main sources
target_sources(${TARGET} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/sources/main.c
)

# Add the applications
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/apps/tls_echo_server)

# Add WolfSSL library
include(WolfSSL.cmake)

