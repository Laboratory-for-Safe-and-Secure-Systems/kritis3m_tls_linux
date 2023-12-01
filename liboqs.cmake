
set(OQS_DIST_BUILD  OFF)
set(OQS_BUILD_ONLY_LIB ON)
set(OQS_USE_OPENSSL OFF)

# Add liboqs to the build environment
add_subdirectory(libs/liboqs oqs)

get_target_property(OQS_BINARY_DIR oqs BINARY_DIR)
# set(CMAKE_PREFIX_PATH "${OQS_BINARY_DIR}")
message("CMAKE_PREFIX_PATH = ${CMAKE_PREFIX_PATH}")


# Add the library to the actual target
# target_link_libraries("${TARGET}" PUBLIC oqs)

# Get the include directories for the target.
# get_target_property(OQS_INCLUDES oqs INCLUDE_DIRECTORIES)
# message("OQS_INCLUDES = ${OQS_INCLUDES}")
# list(GET OQS_INCLUDES 0 OQS_INCLUDE_DIR)
# # message("OQS_INCLUDE_DIR = ${OQS_INCLUDE_DIR}")
# get_target_property(OQS_LIB oqs LIBRARY_OUTPUT_DIRECTORY)
# message("OQS_LIB = ${OQS_LIB}")


# find_path(OQS_INCLUDE_DIR NAMES "oqs/common.h" PATHS ${OQS_INCLUDES})
# message("OQS_INCLUDE_DIR = ${OQS_INCLUDE_DIR}")

# find_library(OQS_LIBRARY NAMES "oqs" PATHS ${OQS_LIB})
# message("OQS_LIBRARY = ${OQS_LIBRARY}")

# Include the toplevel directory for the includes
# target_include_directories("${TARGET}" PUBLIC "${OQS_INCLUDE_DIR}")


# find_path(OQS_INCLUDE_DIR NAMES "oqs/common.h")
# message("OQS_INCLUDE_DIR = ${OQS_INCLUDE_DIR}")

# Include the toplevel directory for the includes
# target_include_directories("${TARGET}" PUBLIC oqs)

# include(FetchContent)

# set(OQS_DIST_BUILD  OFF)
# set(OQS_BUILD_ONLY_LIB ON)
# set(OQS_USE_OPENSSL OFF)

# FetchContent_Declare(
#         OQS
#         PREFIX 
#         SOURCE_DIR ${CMAKE_SOURCE_DIR}/libs/liboqs/
#         BINARY_DIR ${CMAKE_BINARY_DIR}/libs/liboqs/
#         INSTALL_DIR ${CMAKE_BINARY_DIR}/install/ 
#         OVERRIDE_FIND_PACKAGE
#         CMAKE_ARGS
# 	       -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}
# )

# FetchContent_MakeAvailable(OQS)


# find_package(OQS)
# if (OQS)
#         message("MY OQS_LIBRARY = ${OQS_LIBRARY}")
#         message("MY OQS_INCLUDE_DIR = ${OQS_INCLUDE_DIR}")
# endif()

# Add the library to the actual target
# target_link_libraries("${TARGET}" PUBLIC OQS)