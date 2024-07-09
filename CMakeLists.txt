cmake_minimum_required(VERSION 3.22)

# Make sure VSCode and IntelliSense finds its necessary data
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


include(FetchContent)
Set(FETCHCONTENT_QUIET FALSE)


# External repositories we need
FetchContent_Declare(kritis3m_asl
    GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_asl.git
    GIT_TAG                 origin/main
    GIT_PROGRESS            TRUE
)

FetchContent_Declare(kritis3m_applications
    GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_applications.git
    GIT_TAG                 origin/main
    GIT_PROGRESS            TRUE
)


set(TARGET kritis3m_proxy)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cli_parsing.c
)

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

# Actually add the external repositories to our project
FetchContent_GetProperties(kritis3m_asl)
if(NOT kritis3m_asl_POPULATED)
  FetchContent_Populate(kritis3m_asl)
  add_subdirectory(${kritis3m_asl_SOURCE_DIR} ${kritis3m_asl_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

FetchContent_GetProperties(kritis3m_applications)
if(NOT kritis3m_applications_POPULATED)
  FetchContent_Populate(kritis3m_applications)
  add_subdirectory(${kritis3m_applications_SOURCE_DIR} ${kritis3m_applications_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# Link KRITIS3M_ASL to the main target
target_link_libraries(${TARGET} PUBLIC asl)

# Install the executable
install(TARGETS ${TARGET} DESTINATION bin)

# Install the helper scripts
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_forward_proxy.sh DESTINATION bin RENAME kritis3m_forward_proxy)
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_reverse_proxy.sh DESTINATION bin RENAME kritis3m_reverse_proxy)
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_echo_server.sh DESTINATION bin RENAME kritis3m_echo_server)
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_echo_client.sh DESTINATION bin RENAME kritis3m_echo_client)
