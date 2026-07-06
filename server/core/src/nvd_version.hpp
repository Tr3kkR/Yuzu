#pragma once

#include <string_view>

// NVD-grade version comparison and CPE version-range evaluation.
//
// This is deliberately SEPARATE from `yuzu::server::compare_versions`
// (declared in nvd_db.hpp), which is a simpler numeric comparator shared by
// agent_service_impl.cpp (upgrade check) and update_registry.cpp (package
// pick). Those callers must keep their existing semantics, so NVD matching
// gets its own richer comparator here rather than mutating the shared one.
//
// Semantics target NVD `cpeMatch` version ranges: dotted-numeric cores with
// alpha/pre-release suffixes (1.0.2k, 3.0.0-beta, 9.8p1, 124.0.6367.202) and
// inclusive/exclusive start+end bounds plus exact and wildcard CPE versions.

namespace yuzu::server {

/// Compare two version strings NVD-style. Returns <0 if a<b, 0 if a==b, >0 if
/// a>b. Tokenises on '.', '-', '_', '+', '~' AND on digit<->alpha boundaries
/// ("1.0rc2" -> 1 0 rc 2). Numeric segments compare as integers (overflow
/// safe); recognised pre-release tags order dev < alpha/a < beta/b < pre < rc <
/// release; a numeric segment outranks an alpha one at the same position; a
/// trailing pre-release tag makes the longer string LOWER (1.0 > 1.0-rc1) while
/// a trailing non-zero numeric or unknown-alpha segment makes it HIGHER
/// (9.8p1 > 9.8, 1.0.1 > 1.0); trailing zero segments are padding (1.0 ==
/// 1.0.0). A leading "N:" epoch is stripped and ignored — NVD CPE versions
/// never carry epochs, so honouring an inventory-side epoch would push every
/// epoch-bearing package above all NVD bounds (mass false negatives).
int nvd_version_compare(std::string_view a, std::string_view b);

/// A CPE version constraint. Any field may be empty (absent). When one or more
/// of the four bounds is set, they define the vulnerable range and `exact` is
/// ignored. When no bound is set, `exact` (the CPE 2.3 version field) decides:
/// empty / "*" / "-" means "all versions", otherwise an exact pin.
struct VersionRange {
    std::string_view exact;
    std::string_view start_including;
    std::string_view start_excluding;
    std::string_view end_including;
    std::string_view end_excluding;
};

/// True if `installed` falls within the vulnerable range described by `r`.
bool nvd_version_in_range(std::string_view installed, const VersionRange& r);

} // namespace yuzu::server
