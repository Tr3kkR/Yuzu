#pragma once

#include <string_view>

/// Which runtime-config keys hold a credential, and what to print instead.
///
/// A zero-dependency leaf on purpose. Two unrelated stores need this predicate:
/// `RuntimeConfigStore`, which must not emit a secret's value, and `AuditStore`,
/// which must not serve the plaintext an older writer recorded in a row's `detail`.
/// Routing that through `runtime_config_store.hpp` made the evidence substrate
/// depend on a specific domain store (and, transitively, on nlohmann) to reach two
/// static members. Both now depend on this instead, and on nothing else.
///
/// Keep it STL-only. The point is that anything may include it.
namespace yuzu::server {

/// True if this key's VALUE is a credential and must never be emitted in plaintext:
/// not to a log, not to an API response, not to an audit detail, not to a config
/// dump. Unknown keys are not secret -- they are not storable at all.
bool is_secret_config_key(std::string_view key);

/// What to print in place of a secret. ONE spelling, so log scrapers and API
/// consumers see a single token.
///
/// Deliberately `const char*` rather than `std::string_view`: it is concatenated
/// with `std::string` at several call sites, and `std::string + std::string_view`
/// is a C++26 addition (P2591), not available in the C++23 baseline this project
/// builds against. A `string_view` here would fail to compile on every supported
/// compiler.
/// DO NOT respell this to a common word. `is_redaction_placeholder()` refuses any
/// value CONTAINING this token, which is safe only because `<redacted>` is implausible
/// as a substring of a real credential (`<` and `>` are outside the alphabet of every
/// mainstream IdP secret). Changing it to "REDACTED" or "hidden" would silently turn a
/// near-zero-false-positive guard into a broad refusal of legitimate credentials.
inline constexpr const char* kRedactedPlaceholder = "<redacted>";

/// True if `value` is the redaction placeholder, ignoring surrounding whitespace.
///
/// Trimming is the point. An exact comparison let a paste that picked up a trailing
/// newline through the guard and be stored AS the client secret, destroying the real
/// one - the exact outcome the guard exists to prevent. It lives here, and is called
/// from the STORE, so every caller is covered: putting it only in the Settings handler
/// left `PUT /api/config/oidc_client_secret` wide open, which is the same
/// fix-the-instance-not-the-sink mistake in a second costume.
bool is_redaction_placeholder(std::string_view value);

} // namespace yuzu::server
