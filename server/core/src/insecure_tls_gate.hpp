// insecure_tls_gate.hpp — second-confirmation gate for one-way TLS (issue #79).
//
// `--insecure-skip-client-verify` (formerly `--allow-one-way-tls`) disables
// client certificate verification on the agent listener. To make accidental
// activation noisy and intentional activation explicit, the server requires
// BOTH the CLI flag AND `YUZU_ALLOW_INSECURE_TLS=1` in the environment.
//
// The env-var check is intentionally exact-match against the literal string
// "1": "true", "yes", "TRUE", and "0" are all rejected. This avoids the
// historical class of "boolean env var" bugs where operators set
// `YUZU_ALLOW_INSECURE_TLS=true` expecting it to authorize and the parser
// silently treated it as falsey, or vice versa.
//
// Extracted from main.cpp so the gate logic can be unit-tested in isolation
// (`tests/unit/server/test_insecure_tls_gate.cpp`).

#pragma once

#include <cstdlib>
#include <string_view>

namespace yuzu::server::security {

// Canonical literal value the operator must set on the env var. Exposed so
// tests and docs can reference the same constant the gate enforces.
inline constexpr std::string_view kInsecureTlsEnvVar = "YUZU_ALLOW_INSECURE_TLS";
inline constexpr std::string_view kInsecureTlsEnvAuthorizedValue = "1";

// Return true iff the supplied env-var raw value (or nullptr if unset)
// authorizes one-way TLS. Exact-match against "1" — anything else, including
// nullptr, the empty string, "0", "true", "TRUE", or "yes", is rejected.
[[nodiscard]] inline bool insecure_tls_env_authorized(const char* env_value) noexcept {
    if (env_value == nullptr) {
        return false;
    }
    return std::string_view{env_value} == kInsecureTlsEnvAuthorizedValue;
}

// Convenience wrapper that reads the env var by name. Defined here so
// production code and tests share one implementation.
[[nodiscard]] inline bool insecure_tls_env_authorized() noexcept {
    return insecure_tls_env_authorized(std::getenv(kInsecureTlsEnvVar.data()));
}

} // namespace yuzu::server::security
