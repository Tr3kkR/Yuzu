#pragma once

#include <string_view>

namespace yuzu::server {

// Shared error-message prefix that store-layer methods use to signal
// duplicate-resource conflicts (#396, #399, #402, governance Gate 3 arch-B1).
//
// Routes that call create_* on a store check the returned error string with
// `error.rfind(kConflictPrefix, 0) == 0` and map matches to HTTP 409 instead
// of the default 400. The constant lives in one place so a typo on either
// side is a compile error rather than a silent 409→400 downgrade.
//
// New duplicate-class error sites MUST format as:
//   std::string(kConflictPrefix) + " <human-readable detail>"
//
// Routes returning JSON should strip the prefix before placing the message
// in the response body — see strip_conflict_prefix() below.
inline constexpr std::string_view kConflictPrefix = "conflict:";

// Strip the kConflictPrefix (and the single space that follows it in the
// canonical form) from an error string for inclusion in operator-facing
// error responses. Returns the input unchanged if the prefix is absent.
inline std::string_view strip_conflict_prefix(std::string_view msg) {
    if (msg.rfind(kConflictPrefix, 0) != 0)
        return msg;
    auto rest = msg.substr(kConflictPrefix.size());
    while (!rest.empty() && rest.front() == ' ')
        rest.remove_prefix(1);
    return rest;
}

inline bool is_conflict_error(std::string_view msg) {
    return msg.rfind(kConflictPrefix, 0) == 0;
}

// Shared error-message prefix that migrated-store methods use to signal a genuine DB/lease
// failure, distinct from not-found/validation (ADR-0036 typed-read policy; governance Gate 3
// architect finding). Each store previously defined its own independent
// `"db_error: "` literal (`kInstructionStoreDbErrorPrefix`, `kProductPackDbErrorPrefix`) —
// coupled only by string-equality convention, not by type, so a future store adopting a
// differently-spelled prefix would silently fall into a caller's "tolerated" branch instead
// of its "genuine failure, abort" branch (the exact class of bug found in
// `ProductPackStore::uninstall`'s `ItemUninstallFn` classification). New migrated stores
// should reference `kDbErrorPrefix` directly rather than minting their own literal.
inline constexpr std::string_view kDbErrorPrefix = "db_error: ";

} // namespace yuzu::server
