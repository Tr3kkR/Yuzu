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

# libpq (Postgres substrate, ADR-0006) must be STATIC even though the rest of the
# sanitizer dep tree is dynamic — two reasons, both surfaced by the Big Tam cold
# sanitizer build (the deps haven't been rebuilt from source since libpq landed):
#   1. meson.build's unix libpq block hard-requires the static
#      libpgcommon.a/libpgport.a archives (scram/auth helpers) that ONLY the
#      static build emits; a dynamic libpq.so has no standalone pgcommon → meson
#      fails with "library 'pgcommon' not found".
#   2. PostgreSQL's shared-lib `libpq-refs-stamp` check rejects TSan's injected
#      `__tsan_func_exit` symbol as "calling exit" ("libpq must not be calling any
#      function which invokes exit"). vcpkg's libpq Makefile builds the .so only on
#      the `all-shared-lib` path; the static path (`all-static-lib`) skips the .so
#      and that check entirely.
# Matches the stock x64-linux triplet (which is already static). The triplet's
# -fsanitize flags still apply to the static archive, so sanitizer coverage
# inside libpq is preserved.
if(PORT STREQUAL "libpq")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()

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
