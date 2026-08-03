#include "config_secret_keys.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>

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

bool is_redaction_placeholder(std::string_view value) {
    // Two rules, both failing CLOSED, because the cost of a false negative here is
    // destroying a production OIDC credential and the cost of a false positive is
    // refusing an implausible secret with a clear message.
    //
    // 1. Ignore anything at or below 0x20 (space, tab, CR, LF, VT, FF, and the rest
    //    of C0) at either end. An earlier version listed a fixed byte set, which a
    //    reviewer correctly pointed out is not a code-point set: a pasted U+FEFF or
    //    U+200B is multi-byte UTF-8 and survived it.
    // 2. Then refuse anything that CONTAINS the placeholder at all. That is the
    //    catch-all rule 1 cannot give: no trim charset is exhaustive against every
    //    invisible code point someone can paste. A genuine client secret containing
    //    the literal "<redacted>" is implausible; if one exists, rotate it at the IdP.
    const auto keep = [](unsigned char c) { return c > 0x20; };
    std::size_t b = 0, e = value.size();
    while (b < e && !keep(static_cast<unsigned char>(value[b])))
        ++b;
    while (e > b && !keep(static_cast<unsigned char>(value[e - 1])))
        --e;
    const std::string_view trimmed = value.substr(b, e - b);
    if (trimmed.empty())
        return false; // nothing but whitespace is not the placeholder
    return trimmed == kRedactedPlaceholder ||
           trimmed.find(kRedactedPlaceholder) != std::string_view::npos;
}

bool is_secret_config_key(std::string_view key) {
    return std::ranges::find(kSecretKeys, key) != kSecretKeys.end();
}

} // namespace yuzu::server
