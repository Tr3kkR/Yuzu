#pragma once

#include <string>
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

// Shared kind-validation wording (#753) so operators see one message
// regardless of which store rejected their YAML. These are 400s, not
// 409s — do NOT route them through kConflictPrefix.
//
// kind_mismatch_error() covers "kind" present but wrong; kind_missing_error()
// covers "kind" absent entirely — a missing kind is not a mismatch, so it
// gets its own honest verb rather than being force-fitted into the
// mismatch string.
//
// Byte-exact outputs (verify any change against these before committing):
//   kind_mismatch_error("X", "Y") ==
//     "kind must be 'X', got 'Y'. yaml_source must be a complete YAML "
//     "document including 'apiVersion: yuzu.io/v1alpha1' and 'kind: X'."
//   kind_mismatch_error("X", "Y", example) appends " Example:\n" + example
//   kind_mismatch_error("X", "Y", example, docs_ref) further appends
//     "See " + docs_ref + "."
//   kind_missing_error() ==
//     "kind is required. yaml_source must be a complete YAML document "
//     "including 'apiVersion: yuzu.io/v1alpha1' and a 'kind:' field."
inline std::string kind_mismatch_error(std::string_view expected, std::string_view actual,
                                        std::string_view example = {},
                                        std::string_view docs_ref = {}) {
    std::string msg = "kind must be '";
    msg += expected;
    msg += "', got '";
    msg += actual;
    msg += "'. yaml_source must be a complete YAML document including "
           "'apiVersion: yuzu.io/v1alpha1' and 'kind: ";
    msg += expected;
    msg += "'.";
    if (!example.empty()) {
        msg += " Example:\n";
        msg += example;
    }
    if (!docs_ref.empty()) {
        msg += "See ";
        msg += docs_ref;
        msg += ".";
    }
    return msg;
}

inline std::string kind_missing_error() {
    return "kind is required. yaml_source must be a complete YAML document "
           "including 'apiVersion: yuzu.io/v1alpha1' and a 'kind:' field.";
}

} // namespace yuzu::server
