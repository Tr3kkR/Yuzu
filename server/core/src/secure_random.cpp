#include "secure_random.hpp"

#include <spdlog/spdlog.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
// BCRYPT_USE_SYSTEM_PREFERRED_RNG removes the need to open an algorithm
// provider handle — Windows manages the kernel CSPRNG for us. Available on
// Vista+, which is well below our minimum supported Windows version.
#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif
#else
#include <openssl/rand.h>
#endif

#include <cstddef>
#include <limits>
#include <vector>

namespace yuzu::server {

namespace {

constexpr char kHex[] = "0123456789abcdef";

// Thread-local one-shot force-failure flag, set by the test hook below and
// consumed on the next fill_random call. Lives in the anonymous namespace so
// production TUs cannot reach it; the public test_hooks API is the only path
// to flip it. Inert (always false) outside test fixtures.
thread_local bool g_force_failure = false;

} // namespace

std::expected<void, SecureRandomError> fill_random(std::span<std::uint8_t> out) noexcept {
    if (out.empty())
        return {};

    // Honour the test-only force-failure override before touching the CSPRNG
    // so the F-002 audit-emission tests do not depend on an entropy-starved
    // process. The flag is one-shot: consume it and clear on every call so a
    // subsequent legitimate fill in the same test (e.g. fixture teardown
    // creating a fresh token) is not also forced to fail.
    if (g_force_failure) {
        g_force_failure = false;
        return std::unexpected(SecureRandomError::PrngFailure);
    }

#ifdef _WIN32
    // ULONG is 32-bit on every Windows ABI we ship to, so a buffer larger
    // than UINT32_MAX must be split. Token-generation call sites use small
    // fixed sizes (<=64 bytes) but we guard the contract anyway.
    constexpr std::size_t kChunk = static_cast<std::size_t>(0xFFFFFFFFu);
    std::size_t remaining = out.size();
    auto* p = out.data();
    while (remaining > 0) {
        const ULONG step = static_cast<ULONG>(remaining > kChunk ? kChunk : remaining);
        const NTSTATUS rc = BCryptGenRandom(nullptr, p, step, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (rc != 0 /* STATUS_SUCCESS */) {
            spdlog::error("secure_random: BCryptGenRandom failed, NTSTATUS=0x{:08x}",
                          static_cast<unsigned>(rc));
            return std::unexpected(SecureRandomError::PrngFailure);
        }
        p += step;
        remaining -= step;
    }
    return {};
#else
    // RAND_bytes returns 1 on success, 0 on entropy exhaustion / failure,
    // -1 if the method is unimplemented. Anything other than 1 is a hard
    // failure — never fall back to weak entropy.
    if (out.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        spdlog::error("secure_random: requested {} bytes exceeds RAND_bytes int limit", out.size());
        return std::unexpected(SecureRandomError::PrngFailure);
    }
    const int rc = RAND_bytes(out.data(), static_cast<int>(out.size()));
    if (rc != 1) {
        spdlog::error("secure_random: RAND_bytes returned {} (entropy unavailable)", rc);
        return std::unexpected(SecureRandomError::PrngFailure);
    }
    return {};
#endif
}

std::expected<std::string, SecureRandomError> random_hex(std::size_t byte_count) {
    if (byte_count == 0)
        return std::string{};

    std::vector<std::uint8_t> buf(byte_count);
    auto rc = fill_random(buf);
    if (!rc.has_value())
        return std::unexpected(rc.error());

    std::string out;
    out.reserve(byte_count * 2);
    for (std::uint8_t b : buf) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

namespace test_hooks {

void force_next_failure_for_this_thread() {
    g_force_failure = true;
}

bool is_failure_forced_for_this_thread() {
    return g_force_failure;
}

} // namespace test_hooks

} // namespace yuzu::server
