set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)

# DO NOT set(VCPKG_BUILD_TYPE release).
#
# Setting that flag tells vcpkg to skip building the debug variant of
# every package, leaving only release-CRT (`/MD`, `_ITERATOR_DEBUG_LEVEL=0`)
# binaries in `vcpkg_installed/x64-windows/`. Our debug build compiles
# user code with `/MDd` and `_ITERATOR_DEBUG_LEVEL=2`, and if any package
# is built as a STATIC lib with release CRT, the linker refuses to mix
# the two and every Windows debug build will fail with dozens of LNK2038
# "RuntimeLibrary mismatch" / "_ITERATOR_DEBUG_LEVEL mismatch" errors
# against `libprotobuf.lib`, `absl_cord.lib`, `absl_strings.lib`, etc.
#
# The LNK2038 history on this triplet:
#   * f0bb58b (2026-04-10) added `VCPKG_BUILD_TYPE release` to halve
#     install time. Broke every Windows MSVC debug build for 4 days.
#   * 0fe5eac (2026-04-13) reverted that line but kept a hard override
#     forcing static linkage for grpc/protobuf/abseil/upb/re2/c-ares/
#     utf8-range. vcpkg then built both release and debug static
#     variants of each, but meson's cmake dependency probe only reads
#     `IMPORTED_LOCATION_RELEASE` from vcpkg's imported targets and
#     ignores `IMPORTED_LOCATION_DEBUG` — so the debug build still
#     linked against release static libs and still failed with
#     LNK2038. A per-build-type triplet split (#375 option A) and
#     meson `cmake_args: ['-DCMAKE_BUILD_TYPE=Debug']` (option B) both
#     failed to move meson's imported-target resolution.
#   * This revision drops the static override entirely, letting
#     protobuf/grpc/abseil/etc. build as DLLs + import libs. Import
#     libs don't carry CRT variant information — they're "this symbol
#     lives in that DLL" stubs — so debug user code can link against a
#     release-CRT DLL without LNK2038. The DLL itself embeds its own
#     CRT at runtime, which MSVC's loader handles via the `vcruntime*.dll`
#     side-by-side mechanism.
#
# The Linux triplet keeps `VCPKG_BUILD_TYPE release` because gcc/clang
# don't have MSVC's runtime-library variant ABI — debug user code can
# safely link against release-built `.a` static libs.
#
# If a future abseil / grpc / protobuf upgrade reintroduces the
# DLL-symbol-conflict class of problem this override originally
# addressed, the fix is NOT to re-force static linkage here (see
# above for why that doesn't work). Instead, drop meson's cmake dep
# method for those libs on Windows and use `cxx.find_library()` with
# an explicit build-type-conditional search dir (#375 option D, the
# documented fallback).
