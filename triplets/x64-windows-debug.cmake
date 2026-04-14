set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)

# Debug-only build of every package in the install tree. Pair with
# `--triplet x64-windows-debug` and a meson `cmake_prefix_path` pointing
# at `vcpkg_installed/x64-windows-debug/`. The result is an install
# tree that contains ONLY `/MDd` / `_ITERATOR_DEBUG_LEVEL=2` static libs,
# so meson's cmake dep probe cannot pick the wrong variant at link time.
#
# This file exists because the shared `x64-windows.cmake` triplet (which
# builds both debug and release variants) tripped a meson cmake dep
# probe limitation: meson reads `IMPORTED_LOCATION_RELEASE` from the
# imported target regardless of meson's `--buildtype=debug`, so the
# debug build linked against release static libprotobuf and failed with
# LNK2038. See the comment in `x64-windows.cmake` for the LNK2038 history,
# and the P0 issue for the meson cmake-dep details.
set(VCPKG_BUILD_TYPE debug)

# Force static linkage for the grpc stack to avoid abseil DLL symbol
# conflicts (mirrors x64-windows.cmake — keep both files in sync).
if(PORT MATCHES "^(abseil|grpc|protobuf|upb|re2|c-ares|utf8-range)$")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()
