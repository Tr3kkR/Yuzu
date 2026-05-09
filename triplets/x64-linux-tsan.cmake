# x64-linux-tsan triplet — vcpkg builds vendored deps (protobuf, abseil,
# grpc, openssl, sqlite, etc.) with ThreadSanitizer enabled. The Yuzu
# sanitize-tsan CI job uses this triplet so the application's TSan
# instrumentation can observe synchronization primitives inside the
# dependency code, and abseil's TSan-aware container ops engage
# (`ABSL_HAVE_THREAD_SANITIZER` is auto-detected by abseil's build when
# `-fsanitize=thread` is in the compile flags).
#
# Without this, TSan-instrumented Yuzu code passes through non-TSan
# library code paths that hold real locks, and TSan can't observe
# the happens-before edges. Symptoms: false-positive races, missed
# real races, or hard SEGV-without-race-report when TSan's shadow
# memory model collides with a dep's atomic ops it didn't instrument.
# Issue #917.

set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)

# Sanitiser flags propagate to every compiled C/C++ TU in vendored
# dependencies. `-fno-omit-frame-pointer` keeps backtraces accurate
# in race reports; `-g` keeps file:line debug info. Matches what
# meson `-Db_sanitize=thread` emits for the application binary so
# the dep tree and app tree are ABI-compatible.
#
# UBSan is intentionally **not** built into the deps for the same
# reason as x64-linux-asan: `-fsanitize=undefined` instruments
# function-pointer + vptr access in a way that prevents abseil's
# constexpr address-comparison from being constant-evaluated,
# breaking the abseil build. The Yuzu application binary still
# compiles under TSan via meson `-Db_sanitize=thread`; UBSan
# instrumentation in libs adds nothing here.
set(VCPKG_C_FLAGS   "-fsanitize=thread -fno-omit-frame-pointer -g")
set(VCPKG_CXX_FLAGS "-fsanitize=thread -fno-omit-frame-pointer -g")
set(VCPKG_LINKER_FLAGS "-fsanitize=thread")

# Skip dep debug variants — protobuf/abseil/grpc are already large;
# a debug-side build would double the binary-cache footprint and the
# from-source first-run time. Same reasoning as x64-linux-asan.
set(VCPKG_BUILD_TYPE release)
