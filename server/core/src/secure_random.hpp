#pragma once

/**
 * secure_random.hpp — cryptographically-secure random bytes for auth tokens.
 *
 * Backed by `RAND_bytes` on POSIX (OpenSSL — already a hard dep via gRPC TLS)
 * and `BCryptGenRandom` on Windows. Both are FIPS-compliant CSPRNGs. Callers
 * MUST treat failure as a server-side error and surface it to the operator
 * (typically 503 Service Unavailable) — silent fallback to weak entropy is
 * explicitly NOT supported.
 *
 * History: introduced for #801 after @liamsomerville's 2026-05-04 security
 * audit found `DeviceTokenStore` and `ApiTokenStore` using `std::mt19937_64`
 * seeded from `std::random_device`. mt19937 state can be recovered from a
 * small number of outputs, so any token derived from it is forgeable by an
 * attacker who observes one. Both sites now route through this helper.
 *
 * Non-token ID generation (instruction IDs, deployment IDs, etc.) is
 * intentionally NOT routed through here — those are display identifiers,
 * not authenticators. Predictability there has a different blast radius
 * and is tracked separately (see follow-up issues filed alongside #801).
 */

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace yuzu::server {

/// Why fill_random failed. Surfaces in REST/MCP error envelopes as a 503.
enum class SecureRandomError {
    /// Underlying CSPRNG (RAND_bytes / BCryptGenRandom) returned an error.
    /// On POSIX this is OpenSSL's seed pool failure mode — usually entropy
    /// exhaustion in an early-boot or restricted-FD container. On Windows
    /// it indicates BCrypt's provider returned non-success. Either way the
    /// server has no business issuing a token until the next call succeeds.
    PrngFailure,
};

/// Fill `out` with cryptographically-secure random bytes. Empty `out` is a
/// no-op success. On failure the buffer's contents are unspecified — do NOT
/// use the partial result.
[[nodiscard]] std::expected<void, SecureRandomError>
fill_random(std::span<std::uint8_t> out) noexcept;

/// Return `byte_count` bytes of CSPRNG output formatted as lowercase hex
/// (2 * byte_count chars). Convenience wrapper around `fill_random` for the
/// common token-generation case.
[[nodiscard]] std::expected<std::string, SecureRandomError> random_hex(std::size_t byte_count);

namespace test_hooks {

/// Force the next `fill_random` / `random_hex` call on the current thread to
/// return `PrngFailure` without touching the underlying CSPRNG, then auto-clear.
/// Test-only: lets governance Gate 2 F-002 verify that token-create handlers
/// emit a `failure` audit row when entropy is unavailable, without faking
/// an entropy-exhaustion environment. Thread-local so concurrent test cases
/// do not poison one another. Never call from production code.
void force_next_failure_for_this_thread();

/// Inspect the thread-local force flag — exposed for asserting the override
/// has been consumed. Production code must not branch on this.
bool is_failure_forced_for_this_thread();

} // namespace test_hooks

} // namespace yuzu::server
