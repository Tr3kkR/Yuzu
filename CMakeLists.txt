cmake_minimum_required(VERSION 3.28)

project(
  yuzu
  VERSION 0.1.0
  DESCRIPTION "Multi-platform agent and server framework"
  HOMEPAGE_URL "https://github.com/Tr3kkR/Yuzu"
  LANGUAGES CXX
)

# ── C++ standard ─────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Policies ──────────────────────────────────────────────────────────────────
cmake_policy(SET CMP0091 NEW)  # MSVC runtime library via CMAKE_MSVC_RUNTIME_LIBRARY
cmake_policy(SET CMP0135 NEW)  # FetchContent timestamp

# ── Output directories ────────────────────────────────────────────────────────
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# ── Build options ─────────────────────────────────────────────────────────────
option(YUZU_BUILD_AGENT    "Build the agent daemon"          ON)
option(YUZU_BUILD_SERVER   "Build the server daemon"         ON)
option(YUZU_BUILD_SDK      "Build and install the SDK"       ON)
option(YUZU_BUILD_TESTS    "Build tests"                     OFF)
option(YUZU_BUILD_EXAMPLES "Build example plugins"           ON)
option(YUZU_ENABLE_LTO     "Enable link-time optimisation"   OFF)
option(YUZU_ENABLE_ASAN    "Enable AddressSanitizer"         OFF)
option(YUZU_ENABLE_TSAN    "Enable ThreadSanitizer"          OFF)

# ── Compiler flags ────────────────────────────────────────────────────────────
include(cmake/modules/CompilerFlags.cmake)

# ── vcpkg toolchain (auto-detected via VCPKG_ROOT env or CMAKE_TOOLCHAIN_FILE)
# Users set: cmake -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
# Or use CMake presets which set this automatically.

# ── Dependencies (via vcpkg) ──────────────────────────────────────────────────
find_package(gRPC        CONFIG REQUIRED)
find_package(protobuf    CONFIG REQUIRED)
find_package(absl        CONFIG REQUIRED)
find_package(spdlog      CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(CLI11       CONFIG REQUIRED)

# ── Protobuf / gRPC code generation ──────────────────────────────────────────
add_subdirectory(proto)

# ── SDK (public headers + static helper lib) ──────────────────────────────────
if(YUZU_BUILD_SDK)
  add_subdirectory(sdk)
endif()

# ── Agent daemon ──────────────────────────────────────────────────────────────
if(YUZU_BUILD_AGENT)
  add_subdirectory(agents/core)
  if(YUZU_BUILD_EXAMPLES)
    add_subdirectory(agents/plugins/example)
  endif()
endif()

# ── Server daemon ─────────────────────────────────────────────────────────────
if(YUZU_BUILD_SERVER)
  add_subdirectory(server/core)
  add_subdirectory(server/gateway)
endif()

# ── Tests ─────────────────────────────────────────────────────────────────────
if(YUZU_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ── Install rules ─────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(
  DIRECTORY sdk/include/
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
