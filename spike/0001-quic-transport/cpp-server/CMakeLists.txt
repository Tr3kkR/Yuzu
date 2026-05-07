cmake_minimum_required(VERSION 3.20)
project(yuzu_quic_spike_server CXX)

# Spike was validated only on Darwin/arm64 (see
# docs/spike-results/0001-quic-transport/README.md). The toolchain prefix
# below hardcodes `arm64-osx`; building on Linux x64 / Linux arm64 / Windows
# x64 silently picks the wrong vcpkg installed tree and fails with a
# confusing find_package error. Fail loudly here instead — a future
# operator re-running the spike for PR 3 prep will get an actionable
# message and know they must parametrise the triplet
# (governance round 5 build-ci S2 + cross-platform).
if(NOT (CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin"
        AND CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "arm64"))
  message(FATAL_ERROR
    "yuzu QUIC spike validated only on macOS arm64 (see ADR-0001 §Spike "
    "validation gate). To re-run on another platform, replace 'arm64-osx' "
    "in this CMakeLists.txt with the matching vcpkg triplet "
    "(e.g. 'x64-linux', 'arm64-linux', 'x64-windows') and re-run vcpkg "
    "install + cmake configure. The spike is throwaway code; per ADR-0001 "
    "Spike validation gate, multi-platform validation lands as part of "
    "PR 3 (msquic production transport) and PR 4 (quicer gateway).")
endif()

# Throwaway. C++23 to match Yuzu's main toolchain, but no production
# integration here — meson is untouched.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_LIST_DIR}/vcpkg_installed/arm64-osx/share/msquic"
    CACHE FILEPATH "" FORCE)

list(PREPEND CMAKE_PREFIX_PATH
    "${CMAKE_CURRENT_LIST_DIR}/vcpkg_installed/arm64-osx")

find_package(msquic CONFIG REQUIRED)

add_executable(yuzu_quic_spike_server src/server.cpp)
target_link_libraries(yuzu_quic_spike_server PRIVATE msquic)
target_compile_options(yuzu_quic_spike_server PRIVATE -Wall -Wextra)

# Bake the rpath so the executable finds libmsquic.dylib next to vcpkg_installed.
set_target_properties(yuzu_quic_spike_server PROPERTIES
    BUILD_RPATH "${CMAKE_CURRENT_LIST_DIR}/vcpkg_installed/arm64-osx/lib"
    INSTALL_RPATH "${CMAKE_CURRENT_LIST_DIR}/vcpkg_installed/arm64-osx/lib")
