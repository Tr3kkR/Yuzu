#include "config_secret_keys.hpp"

#include <algorithm>
#include <array>

namespace yuzu::server {

// Constant-initialised, so there is no static-initialisation-order question at all:
// `AuditStore::query()` reaches this from another TU, and a dynamically-initialised
// namespace-scope vector would have been safe only by audit (no static-duration
// caller exists today) rather than by construction.
//
// Adding a secret-valued key to RuntimeConfigStore's allow-list without adding it
// here is the mistake this list exists to make hard: the value would go straight to
// the startup log, GET /api/config, the PUT audit detail and the PUT response echo.
// The name-shaped TRIPWIRE in test_runtime_config_secret_redaction.cpp catches the
// common spellings. Before adding one, also grep the `get(`/`get_value(` call sites
// for it -- redaction changes what an existing FUNCTIONAL consumer receives, and
// that failure is silent.
inline constexpr std::array<std::string_view, 1> kSecretKeys{
    "oidc_client_secret",
};

bool is_secret_config_key(std::string_view key) {
    return std::ranges::find(kSecretKeys, key) != kSecretKeys.end();
}

} // namespace yuzu::server
