
# All WolfSSL configuration is done in the user_settings.h file
set(WOLFSSL_USER_SETTINGS "yes")

# Build neither the examples nor the test stuff
set(WOLFSSL_EXAMPLES "no")
set(WOLFSSL_CRYPT_TESTS "no")
set(BUILD_SHARED_LIBS "no")
set(WOLFSSL_OQS "yes")


# Add WolfSSL to the build environment
add_subdirectory(libs/wolfssl wolfssl)


# In order for WolfSSL to find the 'user_settings.h' file, we have to
# provide the directory where it is located.
target_include_directories(wolfssl PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/config/wolfssl>)


# Add the library to the actual target
target_link_libraries(${TARGET} PUBLIC wolfssl)


