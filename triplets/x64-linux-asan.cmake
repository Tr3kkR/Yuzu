# x64-linux-asan triplet — vcpkg builds vendored deps (protobuf, abseil,
# grpc, etc.) with AddressSanitizer + UndefinedBehaviorSanitizer enabled.
# The Yuzu sanitize-asan CI job uses this triplet so the application's
# ASan instrumentation cooperates with abseil's container-poisoning
# logic (`ABSL_HAVE_ADDRESS_SANITIZER` is auto-detected by abseil's
# build when `-fsanitize=address` is in the compile flags).
#
# Without this, abseil's flat_hash_map poisons unused container slots
# at static-init time (during protobuf's DescriptorPool::Tables
# constructor), and gcc 13's libstdc++ basic_string SSO inline-buffer
# read on an adjacent slot trips a spurious `use-after-poison` ASan
# error before any Yuzu test runs. Issue around governance pipeline,
# v0.12.0-rc /test sweep.

set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)

# Sanitiser flags propagate to every compiled C/C++ TU in vendored
# dependencies. `-fno-omit-frame-pointer` keeps backtraces accurate;
# `-g` keeps file:line debug info.
set(VCPKG_C_FLAGS   "-fsanitize=address,undefined -fno-omit-frame-pointer -g")
set(VCPKG_CXX_FLAGS "-fsanitize=address,undefined -fno-omit-frame-pointer -g")
set(VCPKG_LINKER_FLAGS "-fsanitize=address,undefined")

# Skip dep debug variants — the sanitiser job builds protobuf/abseil/
# grpc (already large); a debug-side build would double the binary-
# cache footprint and the from-source first-run time.
set(VCPKG_BUILD_TYPE release)
