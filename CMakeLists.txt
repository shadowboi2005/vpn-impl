cmake_minimum_required(VERSION 3.22)

# Must run before project(), because project() is what compiles the test program
# that this fixes. Clang picks the highest-numbered GCC toolchain directory it
# finds, which on a machine with libstdc++-13-dev but a stray gcc-14 directory
# leaves it unable to find libstdc++.so. Point it at the newest GCC install that
# actually has one. Harmless where clang already picks correctly.
if(CMAKE_CXX_COMPILER MATCHES "clang")
  file(GLOB _gcc_libstdcxx /usr/lib/gcc/*/*/libstdc++.so)
  if(_gcc_libstdcxx)
    list(SORT _gcc_libstdcxx COMPARE NATURAL ORDER DESCENDING)
    list(GET _gcc_libstdcxx 0 _gcc_libstdcxx_newest)
    get_filename_component(_gcc_install_dir "${_gcc_libstdcxx_newest}" DIRECTORY)
    set(CMAKE_CXX_FLAGS_INIT "--gcc-install-dir=${_gcc_install_dir}")
    message(STATUS "clang: using GCC install dir ${_gcc_install_dir}")
  endif()
endif()

project(vpn_impl LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "build type" FORCE)
endif()

# On by default: PLAN.md requires debug and test builds to run under
# ASan+UBSan, and requires that to be true from Phase 1 rather than bolted on
# later. Release builds turn it off and keep the warnings.
option(VPN_SANITIZE "build with AddressSanitizer and UndefinedBehaviorSanitizer" ON)

add_library(vpn_flags INTERFACE)
target_compile_features(vpn_flags INTERFACE cxx_std_20)
target_compile_options(vpn_flags INTERFACE -Wall -Wextra -Wpedantic -Werror)

if(VPN_SANITIZE)
  target_compile_options(vpn_flags INTERFACE
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined)
  target_link_options(vpn_flags INTERFACE -fsanitize=address,undefined)
  target_compile_definitions(vpn_flags INTERFACE _GLIBCXX_ASSERTIONS)
endif()

# ------------------------------------------------------------ dependencies ---

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# BLAKE2s. libsodium ships BLAKE2b, which is a different algorithm and not a
# parameter you can set, so the hash comes from the BLAKE2 authors' own library,
# vendored as a submodule.
set(LIBB2_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libb2)
if(NOT EXISTS ${LIBB2_DIR}/src/blake2s-ref.c)
  message(FATAL_ERROR
    "third-party/libb2 is empty. Run: git submodule update --init --recursive")
endif()

enable_language(C)

# Only the reference implementation, not libb2's whole autotools build: it is
# the one file we need, it is portable C, and the SIMD variants would drag in
# runtime dispatch for a hash that runs a handful of times per handshake.
add_library(blake2s STATIC ${LIBB2_DIR}/src/blake2s-ref.c)
target_include_directories(blake2s SYSTEM PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libb2-config
  ${LIBB2_DIR}/src)
# Someone else's code: instrument it like ours, but do not hold it to our
# warning settings. -w rather than an exemption list, so an upstream change
# never breaks our build.
target_compile_options(blake2s PRIVATE -w)
if(VPN_SANITIZE)
  target_compile_options(blake2s PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(blake2s PUBLIC -fsanitize=address,undefined)
endif()

add_library(vpncore STATIC
  src/tun.cpp
  src/udp.cpp
  src/netcfg.cpp
  src/wire.cpp
  src/crypto.cpp
  src/noise.cpp
  src/session.cpp
  src/relay.cpp)
target_include_directories(vpncore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(vpncore PUBLIC vpn_flags blake2s PkgConfig::SODIUM)

add_executable(vpnd src/vpnd.cpp)
target_link_libraries(vpnd PRIVATE vpncore)

add_executable(vpn src/vpn.cpp)
target_link_libraries(vpn PRIVATE vpncore)

add_executable(vpnkey src/vpnkey.cpp)
target_link_libraries(vpnkey PRIVATE vpncore)

# ------------------------------------------------------------------- tests ---

enable_testing()

add_executable(wire_test test/unit/wire_test.cpp)
target_include_directories(wire_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test/unit)
target_link_libraries(wire_test PRIVATE vpncore)
add_test(NAME wire COMMAND wire_test)

add_executable(crypto_test test/unit/crypto_test.cpp)
target_include_directories(crypto_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test/unit)
target_link_libraries(crypto_test PRIVATE vpncore)
add_test(NAME crypto COMMAND crypto_test)

add_executable(noise_test test/unit/noise_test.cpp)
target_include_directories(noise_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test/unit)
target_link_libraries(noise_test PRIVATE vpncore)
add_test(NAME noise COMMAND noise_test)

add_executable(session_test test/unit/session_test.cpp)
target_include_directories(session_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test/unit)
target_link_libraries(session_test PRIVATE vpncore)
add_test(NAME session COMMAND session_test)

# libFuzzer is a clang feature. The fuzz target is opt-in rather than part of the
# default build, because -fsanitize=fuzzer replaces main().
option(VPN_FUZZ "build the libFuzzer harnesses (clang only)" OFF)

if(VPN_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "VPN_FUZZ needs clang; ${CMAKE_CXX_COMPILER_ID} has no libFuzzer")
  endif()
  add_executable(decode_fuzz test/fuzz/decode_fuzz.cpp src/wire.cpp)
  target_include_directories(decode_fuzz PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_options(decode_fuzz PRIVATE
    -Wall -Wextra -Wpedantic -Werror
    -fsanitize=fuzzer,address,undefined
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined)
  target_link_options(decode_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
  target_compile_definitions(decode_fuzz PRIVATE _GLIBCXX_ASSERTIONS)

  add_executable(handshake_fuzz test/fuzz/handshake_fuzz.cpp
    src/wire.cpp src/crypto.cpp src/noise.cpp)
  target_include_directories(handshake_fuzz PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_options(handshake_fuzz PRIVATE
    -Wall -Wextra -Wpedantic -Werror
    -fsanitize=fuzzer,address,undefined
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined)
  target_link_options(handshake_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
  target_compile_definitions(handshake_fuzz PRIVATE _GLIBCXX_ASSERTIONS)
  target_link_libraries(handshake_fuzz PRIVATE blake2s PkgConfig::SODIUM)

  add_executable(session_fuzz test/fuzz/session_fuzz.cpp
    src/wire.cpp src/crypto.cpp src/noise.cpp src/session.cpp)
  target_include_directories(session_fuzz PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_options(session_fuzz PRIVATE
    -Wall -Wextra -Wpedantic -Werror
    -fsanitize=fuzzer,address,undefined
    -fno-omit-frame-pointer
    -fno-sanitize-recover=undefined)
  target_link_options(session_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
  target_compile_definitions(session_fuzz PRIVATE _GLIBCXX_ASSERTIONS)
  target_link_libraries(session_fuzz PRIVATE blake2s PkgConfig::SODIUM)
endif()
