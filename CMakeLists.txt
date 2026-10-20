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
# Build channel-c from the sibling source tree so its fixes are always picked
# up. Set HUB_SERVICE_C_PREBUILT_CHANNEL=ON to link channel-c's own build/
# tree instead (faster, but it can be stale).
# ---------------------------------------------------------------------------
set(CHANNEL_C_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../Channel/channel-c")

option(HUB_SERVICE_C_PREBUILT_CHANNEL "Link channel-c's prebuilt build/libchannel_c.a" OFF)

if(NOT TARGET channel_c)
  if(HUB_SERVICE_C_PREBUILT_CHANNEL AND EXISTS "${CHANNEL_C_DIR}/build/libchannel_c.a")
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
  src/crypto.c
  src/device.c
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
    OpenSSL::Crypto
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

# Device layer test vectors, shared by every SDK (Hub/Docs/Devices).
set(HUB_DEVICE_VECTORS "${CMAKE_CURRENT_SOURCE_DIR}/../../Docs/Devices/vectors.json")
add_executable(test_vectors tests/test_vectors.c)
target_compile_definitions(test_vectors PRIVATE HUB_DEVICE_VECTORS="${HUB_DEVICE_VECTORS}")
target_link_libraries(test_vectors PRIVATE hub_service_c PkgConfig::CMOCKA)
add_test(NAME unit_vectors COMMAND test_vectors)

add_executable(test_hub_flow tests/test_hub_flow.c)
target_include_directories(test_hub_flow PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(test_hub_flow PRIVATE hub_service_c PkgConfig::CMOCKA)
add_test(NAME hub_flow COMMAND test_hub_flow)

add_executable(test_device tests/test_device.c)
target_include_directories(test_device PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(test_device PRIVATE hub_service_c PkgConfig::CMOCKA)
add_test(NAME unit_device COMMAND test_device)

# No test may create the real ~/.hub/device.key.
set_tests_properties(unit_service unit_keychain unit_vectors hub_flow unit_device PROPERTIES
  ENVIRONMENT "HUB_DEVICE_KEY=${CMAKE_CURRENT_BINARY_DIR}/test-device.key")
