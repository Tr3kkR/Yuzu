set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)

# Release-only build of every package in the install tree. Pair with
# `--triplet x64-windows-release` and a meson `cmake_prefix_path`
# pointing at `vcpkg_installed/x64-windows-release/`. Counterpart to
# `x64-windows-debug.cmake`. The install tree contains ONLY `/MD` /
# `_ITERATOR_DEBUG_LEVEL=0` static libs.
#
# This is also what the original `f0bb58b` `VCPKG_BUILD_TYPE release`
# optimization tried to do via the shared default — except that
# silently broke debug builds for 4 days. Per-triplet split is the
# correct way to opt into the install-time speedup without breaking
# the other matrix leg.
set(VCPKG_BUILD_TYPE release)

# Force static linkage for the grpc stack to avoid abseil DLL symbol
# conflicts (mirrors x64-windows.cmake — keep both files in sync).
if(PORT MATCHES "^(abseil|grpc|protobuf|upb|re2|c-ares|utf8-range)$")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()
