cmake_minimum_required(VERSION 3.20)
project(hub_service_c VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(LIBWEBSOCKETS REQUIRED IMPORTED_TARGET libwebsockets)
pkg_check_modules(YYJSON REQUIRED IMPORTED_TARGET yyjson)
pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

# ---------------------------------------------------------------------------
# sibling channel-c dependency (read-only; never edited by this repo)
#
# Prefer channel-c's build tree (fast, keeps this project's ctest output
# focused on hub_service_c tests). Fall back to add_subdirectory on the
# sibling source tree when no build tree exists yet.
# ---------------------------------------------------------------------------
set(CHANNEL_C_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../channel-c")

if(NOT TARGET channel_c)
  if(EXISTS "${CHANNEL_C_DIR}/build/libchannel_c.a")
    add_library(channel_c STATIC IMPORTED)
    set_target_properties(channel_c PROPERTIES
      IMPORTED_LOCATION "${CHANNEL_C_DIR}/build/libchannel_c.a"
      INTERFACE_INCLUDE_DIRECTORIES "${CHANNEL_C_DIR}/include"
      INTERFACE_LINK_LIBRARIES
        "PkgConfig::LIBWEBSOCKETS;PkgConfig::YYJSON;OpenSSL::SSL;OpenSSL::Crypto"
    )
    message(STATUS "hub_service_c: linking channel-c from its build tree")
  elseif(EXISTS "${CHANNEL_C_DIR}/CMakeLists.txt")
    add_subdirectory("${CHANNEL_C_DIR}" channel-c-build)
    message(STATUS "hub_service_c: building channel-c from source (add_subdirectory)")
  else()
    message(FATAL_ERROR "channel-c not found at ${CHANNEL_C_DIR}")
  endif()
endif()

# ---------------------------------------------------------------------------
# hub_service_c static library
# ---------------------------------------------------------------------------
add_library(hub_service_c STATIC
  src/hub_service_c.c
  src/keychain.c
)

target_include_directories(hub_service_c
  PUBLIC
    ${PROJECT_SOURCE_DIR}/include
  PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(hub_service_c
  PUBLIC
    channel_c
    PkgConfig::YYJSON
)

# ---------------------------------------------------------------------------
# example binary
# ---------------------------------------------------------------------------
add_executable(echo example/echo.c)
target_link_libraries(echo PRIVATE hub_service_c)

# ---------------------------------------------------------------------------
# unit tests
# ---------------------------------------------------------------------------
enable_testing()

add_executable(test_service tests/test_service.c)
target_include_directories(test_service PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(test_service PRIVATE hub_service_c PkgConfig::CMOCKA)
add_test(NAME unit_service COMMAND test_service)

add_executable(test_keychain tests/test_keychain.c)
target_include_directories(test_keychain PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(test_keychain PRIVATE hub_service_c PkgConfig::CMOCKA)
add_test(NAME unit_keychain COMMAND test_keychain)
