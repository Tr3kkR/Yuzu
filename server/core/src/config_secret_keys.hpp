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
inline constexpr const char* kRedactedPlaceholder = "<redacted>";

} // namespace yuzu::server
