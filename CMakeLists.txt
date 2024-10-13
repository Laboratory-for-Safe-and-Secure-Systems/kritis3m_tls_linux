cmake_minimum_required(VERSION 3.22)

project(kritis3m_tls)

include(GNUInstallDirs)
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Necessary to allow FetchContent_Populate
cmake_policy(SET CMP0169 OLD)


# Options

# When enabled, the application will be built as a self-contained executable with all
# dependencies included. When disabled, it dynamically loads the dependencies
# at runtime.
option(KRITIS3M_TLS_SELF_CONTAINED "Build a self-contained executable" ON)

# Use an externally installed ASL library. If disabled, ASL will be built.
option(KRITIS3M_TLS_EXTERNAL_ASL "Use external ASL library" OFF)


# Define the main executable
add_executable(kritis3m_tls)
target_include_directories(kritis3m_tls PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/includes
)

target_sources(kritis3m_tls PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cli_parsing.c
)
target_compile_options(kritis3m_tls PUBLIC
        -march=native
        -fomit-frame-pointer
        -fdata-sections
        -ffunction-sections
        # -Wl,--gc-sections
)

if (NOT MSVC)
        target_compile_options(kritis3m_tls PUBLIC
                -Wall
                -Wextra
                -Wpedantic
                -Werror
                # -Wa,--noexecstack
                -Wl,--gc-sections
        )
endif()

# When building a self-contained executable, we need to build static libraries. Otherwise,
# we build shared libraries to save space and prevent multiple-definition problems.
if(KRITIS3M_TLS_SELF_CONTAINED)
        set(BUILD_SHARED_LIBS OFF)
else()
        set(BUILD_SHARED_LIBS ON)
endif()


# Add the KRITIS3M_APPLICATION dependency
FetchContent_Declare(kritis3m_applications
        GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_applications.git
        GIT_TAG                 origin/main
        GIT_PROGRESS            TRUE
)
FetchContent_GetProperties(kritis3m_applications)
if(NOT kritis3m_applications_POPULATED)
        FetchContent_Populate(kritis3m_applications)
        add_subdirectory(${kritis3m_applications_SOURCE_DIR} ${kritis3m_applications_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()


# Add the KRITIS3M_ASL dependency
if(KRITIS3M_TLS_EXTERNAL_ASL)
        # Search for system-wide installed KRITIS3M_ASL
        find_package(kritis3m_asl REQUIRED)

else(KRITIS3M_TLS_EXTERNAL_ASL)
        # Add KRITIS3M_ASL as a dependency and build it
        FetchContent_Declare(kritis3m_asl
                GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_asl.git
                GIT_TAG                 origin/main
                GIT_PROGRESS            TRUE
        )

        if(KRITIS3M_TLS_SELF_CONTAINED)
                set(KRITIS3M_ASL_STANDALONE OFF)
        else()
                set(KRITIS3M_ASL_STANDALONE ON)
        endif()
        set(KRITIS3M_ASL_ENABLE_PKCS11 OFF)
        set(KRITIS3M_ASL_PKCS11_CRYPTO OFF)

        FetchContent_GetProperties(kritis3m_asl)
        if(NOT kritis3m_asl_POPULATED)
                FetchContent_Populate(kritis3m_asl)
                if(KRITIS3M_TLS_SELF_CONTAINED)
                        add_subdirectory(${kritis3m_asl_SOURCE_DIR} ${kritis3m_asl_BINARY_DIR} EXCLUDE_FROM_ALL)
                else()
                        add_subdirectory(${kritis3m_asl_SOURCE_DIR} ${kritis3m_asl_BINARY_DIR})
                endif()
        endif()
endif(KRITIS3M_TLS_EXTERNAL_ASL)


# Link the KRITIS3M_APPLICATIONS targets
target_link_libraries(kritis3m_tls PUBLIC kritis3m_applications_common)
target_link_libraries(kritis3m_tls PUBLIC kritis3m_applications_echo_server)
target_link_libraries(kritis3m_tls PUBLIC kritis3m_applications_tcp_client_stdin_bridge)
target_link_libraries(kritis3m_tls PUBLIC kritis3m_applications_proxy)
target_link_libraries(kritis3m_tls PUBLIC kritis3m_applications_network_tester)


# Link KRITIS3M_ASL to the required KRITIS3M_APPLICATIONS targets
target_link_libraries(kritis3m_applications_proxy PUBLIC kritis3m_asl)
target_link_libraries(kritis3m_applications_network_tester PUBLIC kritis3m_asl)
target_link_libraries(kritis3m_applications_echo_server PUBLIC kritis3m_asl)


# Link KRITIS3M_ASL to the main target
target_link_libraries(kritis3m_tls PUBLIC kritis3m_asl)


# Install the executables
install(TARGETS kritis3m_tls DESTINATION ${CMAKE_INSTALL_BINDIR})


# Install the helper scripts
if(WIN32)
        install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_forward_proxy.ps1
                DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME kritis3m_forward_proxy.ps1)
        install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_reverse_proxy.ps1
                DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME kritis3m_reverse_proxy.ps1)
        install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_echo_server.ps1
                DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME kritis3m_echo_server.ps1)
else()
        install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_forward_proxy.sh
                DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME kritis3m_forward_proxy)
        install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_reverse_proxy.sh
                DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME kritis3m_reverse_proxy)
        install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_echo_server.sh
                DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME kritis3m_echo_server)
        install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_echo_server_proxy.sh
                DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME kritis3m_echo_server_proxy)
        install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_client.sh
                DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME kritis3m_tls_client)
        install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/network_tester.sh
                DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME kritis3m_network_tester)
        install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/network_tester_proxy.sh
                DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME kritis3m_network_tester_proxy)
endif()
