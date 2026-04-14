set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)

# DO NOT set(VCPKG_BUILD_TYPE release).
#
# Setting that flag tells vcpkg to skip building the debug variant of
# every package, leaving only release-CRT (`/MD`, `_ITERATOR_DEBUG_LEVEL=0`)
# binaries in `vcpkg_installed/x64-windows/`. Our debug build compiles
# user code with `/MDd` and `_ITERATOR_DEBUG_LEVEL=2`, and MSVC's
# linker refuses to mix the two — every Windows debug build will fail
# with dozens of LNK2038 "RuntimeLibrary mismatch" / "_ITERATOR_DEBUG_LEVEL
# mismatch" errors against `absl_cord.lib`, `absl_strings.lib`, etc.
#
# Commit f0bb58b (2026-04-10) added `VCPKG_BUILD_TYPE release` to halve
# the release-build vcpkg install time. It silently broke every Windows
# MSVC debug build for 4 days (no green ci.yml run on dev between
# 2026-04-10 and 2026-04-14, and the CodeQL Windows matrix leg also
# tripped on it once it got past path/shell quirks).
#
# The Linux triplet keeps `VCPKG_BUILD_TYPE release` because gcc/clang
# don't have MSVC's runtime-library variant ABI — debug user code can
# safely link against release-built `.a` static libs.
#
# If you want the install-time optimization back on Windows, do it via
# per-build-type triplets (`x64-windows-release` for the release matrix
# leg only) — never on the shared default.

# Force static linkage for grpc stack to avoid abseil DLL symbol conflicts
if(PORT MATCHES "^(abseil|grpc|protobuf|upb|re2|c-ares|utf8-range)$")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()
