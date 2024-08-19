cmake_minimum_required(VERSION 3.22)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(TARGET kritis3m_proxy)
project(${TARGET})

# Options

# When enabled, the proxy will be built as a self-contained executable with all
# dependencies included. When disabled, the proxy dynamically loads the dependencies
# at runtime.
option(KRITIS3M_PROXY_SELF_CONTAINED "Build a self-contained proxy" ON)

# Use an externally installed ASL library. If disabled, ASL will be built.
option(KRITIS3M_PROXY_EXTERNAL_ASL "Use external ASL library" OFF)


# External repositories we need
include(FetchContent)
Set(FETCHCONTENT_QUIET FALSE)
FetchContent_Declare(kritis3m_applications
        GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_applications.git
        GIT_TAG                 origin/main
        GIT_PROGRESS            TRUE
)
FetchContent_Declare(kritis3m_asl
        GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_asl.git
        GIT_TAG                 origin/main
        GIT_PROGRESS            TRUE
)


# Define the main executable
add_executable(${TARGET})

# Include directories
target_include_directories(${TARGET} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/config
        ${CMAKE_CURRENT_SOURCE_DIR}/includes
)

# Main sources
target_sources(${TARGET} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cli_parsing.c
)

# Compiler options
target_compile_options(${TARGET} PUBLIC
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -march=native
        -Wa,--noexecstack
        -fomit-frame-pointer
        -fdata-sections
        -ffunction-sections
        -Wl,--gc-sections
)

if(KRITIS3M_PROXY_SELF_CONTAINED)
        set(BUILD_SHARED_LIBS OFF)
else()
        set(BUILD_SHARED_LIBS ON)
endif()

# Actually add the external repositories to our project
FetchContent_GetProperties(kritis3m_applications)
if(NOT kritis3m_applications_POPULATED)
        FetchContent_Populate(kritis3m_applications)
        add_subdirectory(${kritis3m_applications_SOURCE_DIR} ${kritis3m_applications_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

if(KRITIS3M_PROXY_EXTERNAL_ASL)

# Search for system-wide installed KRITIS3M_ASL
find_package(asl NAMES kritis3m_asl REQUIRED)

else(KRITIS3M_PROXY_EXTERNAL_ASL)

# Add KRITIS3M_ASL as a dependency and build it
set(KRITIS3M_ASL_ENABLE_PKCS11 ON)
set(KRITIS3M_ASL_STANDALONE NOT ${KRITIS3M_PROXY_SELF_CONTAINED})
FetchContent_GetProperties(kritis3m_asl)
if(NOT kritis3m_asl_POPULATED)
        FetchContent_Populate(kritis3m_asl)

        if(KRITIS3M_PROXY_SELF_CONTAINED)
                add_subdirectory(${kritis3m_asl_SOURCE_DIR} ${kritis3m_asl_BINARY_DIR} EXCLUDE_FROM_ALL)
        else()
                add_subdirectory(${kritis3m_asl_SOURCE_DIR} ${kritis3m_asl_BINARY_DIR})
        endif()
endif()

endif(KRITIS3M_PROXY_EXTERNAL_ASL)

# Link the KRITIS3M_APPLICATIONS targets
target_link_libraries(${TARGET} PUBLIC kritis3m_applications_common)
target_link_libraries(${TARGET} PUBLIC kritis3m_applications_tcp_echo_server)
target_link_libraries(${TARGET} PUBLIC kritis3m_applications_tcp_client_stdin_bridge)
target_link_libraries(${TARGET} PUBLIC kritis3m_applications_proxy)

# Link KRITIS3M_ASL to the KRITIS3M_APPLICATIONS_Proxy target
target_link_libraries(kritis3m_applications_proxy PUBLIC asl)

# Link KRITIS3M_ASL to the main target
target_link_libraries(${TARGET} PUBLIC asl)

# Install the executable
install(TARGETS ${TARGET} DESTINATION bin)

# Install the helper scripts
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_forward_proxy.sh DESTINATION bin RENAME kritis3m_forward_proxy)
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_reverse_proxy.sh DESTINATION bin RENAME kritis3m_reverse_proxy)
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_echo_server.sh DESTINATION bin RENAME kritis3m_echo_server)
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_client.sh DESTINATION bin RENAME kritis3m_tls_client)
