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


set(TARGET kritis3m_tls)

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

FetchContent_MakeAvailable(kritis3m_asl kritis3m_applications)

# Link WolfSSL to the main target
target_link_libraries(${TARGET} PUBLIC asl)
