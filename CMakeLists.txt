cmake_minimum_required(VERSION 3.24)

include(FetchContent)

set(TARGET kritis3m_tls)

# Make sure VSCode and IntelliSense finds its necessary data
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#External repositories we need 
FetchContent_Declare(tls_echo_server
    GIT_REPOSITORY git@lab.las3.de:frt42716/tls_echo_server.git
    GIT_TAG        secure_element
    GIT_PROGRESS   TRUE
    SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/apps/tls_echo_server
    BINARY_DIR     ${CMAKE_CURRENT_BINARY_DIR}/apps/tls_echo_server
)

FetchContent_Declare(liboqs
    GIT_REPOSITORY https://github.com/Frauschi/liboqs.git
    GIT_TAG        main
    GIT_PROGRESS   TRUE
    SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/libs/liboqs
    BINARY_DIR     ${CMAKE_CURRENT_BINARY_DIR}/libs/liboqs 
)

FetchContent_Declare(wolfssl
    GIT_REPOSITORY https://github.com/Frauschi/wolfssl.git
    GIT_TAG        pq_secure_element
    GIT_PROGRESS   TRUE
    SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/libs/wolfssl
    BINARY_DIR     ${CMAKE_CURRENT_BINARY_DIR}/libs/wolfssl  
)

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


# Liboqs configuration
set(OQS_DIST_BUILD  OFF)
set(OQS_BUILD_ONLY_LIB ON)
set(OQS_USE_OPENSSL OFF)

# WolfSSL configuration
set(WOLFSSL_USER_SETTINGS ON)
set(WOLFSSL_EXAMPLES OFF)
set(WOLFSSL_CRYPT_TESTS OFF)
set(BUILD_SHARED_LIBS OFF)
set(WOLFSSL_OQS OFF)

FetchContent_MakeAvailable(tls_echo_server liboqs wolfssl)

# In order for WolfSSL to find the 'user_settings.h' file, we have to
# provide the directory where it is located.
target_include_directories(wolfssl PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/config/wolfssl>)

# Provide the liboqs headers (generated during build) for WolfSSL
get_target_property(OQS_BINARY_DIR oqs BINARY_DIR)
target_include_directories(wolfssl PUBLIC $<BUILD_INTERFACE:${OQS_BINARY_DIR}/../include>)

# Link liboqs to WolfSSL
target_link_libraries(wolfssl PRIVATE oqs)

# Link WolfSSL to the main target
target_link_libraries(${TARGET} PUBLIC wolfssl)
