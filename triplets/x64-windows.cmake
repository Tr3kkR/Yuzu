set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)

# This is the FALLBACK Windows triplet. Yuzu's CI uses per-build-type
# triplets — see `x64-windows-debug.cmake` and `x64-windows-release.cmake`
# — and CI workflows pass `--triplet x64-windows-{debug,release}`
# directly. This file builds BOTH debug and release variants in a
# single `vcpkg_installed/x64-windows/` tree and is kept around as a
# fallback for tooling that doesn't know about the per-build-type split
# (local developers running `vcpkg install` without a triplet override,
# legacy build scripts, etc.).
#
# Issue #375 — meson's cmake dependency probe reads
# `IMPORTED_LOCATION_RELEASE` from imported targets regardless of
# meson's `--buildtype=debug`, so even when this triplet correctly
# builds both debug and release static libprotobuf, the debug build
# links against the release variant and fails with LNK2038
# `_ITERATOR_DEBUG_LEVEL` mismatches. The per-build-type triplets fix
# this by ensuring exactly one variant exists in each install tree.
#
# Historical context (the fix that unmasked this latent bug):
# Commit f0bb58b (2026-04-10) added `VCPKG_BUILD_TYPE release` here to
# halve the release-build vcpkg install time. It silently broke every
# Windows MSVC debug build for 4 days. Commit 0fe5eac (2026-04-13)
# reverted that line but didn't go all the way to per-build-type
# triplets, so the build was still broken — just in a more subtle
# way that only surfaces past the link step. The cancel-in-progress
# concurrency on dev hid the failure for an unknown duration until
# the 2026-04-14 self-hosted runner migration finally outran the
# cancel-chain timing and exposed the LNK2038 to a completed CI cycle.
#
# The Linux triplet keeps `VCPKG_BUILD_TYPE release` because gcc/clang
# don't have MSVC's runtime-library variant ABI — debug user code can
# safely link against release-built `.a` static libs.

# Force static linkage for grpc stack to avoid abseil DLL symbol conflicts
if(PORT MATCHES "^(abseil|grpc|protobuf|upb|re2|c-ares|utf8-range)$")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()
