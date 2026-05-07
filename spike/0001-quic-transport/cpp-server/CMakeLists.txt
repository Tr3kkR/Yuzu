cmake_minimum_required(VERSION 3.20)
project(yuzu_quic_spike_server CXX)

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
