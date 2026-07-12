/// @file cpe_identity_resolver.cpp
/// CpeIdentityResolver implementation (PR 3, ADR-0018). Pure — no store, NVD,
/// engine, or Postgres coupling. See the header for the resolved-matching
/// model (curated hit => exact product; vendor is display-only).

#include "cpe_identity_resolver.hpp"

#include "cpe_normalize.hpp"            // is_lane1, is_os_native, normalize_product, curated_key, parse_curated_csv
#include "software_inventory_store.hpp" // SoftwareEntry

#include <spdlog/spdlog.h>

#include <stdexcept>
#include <string>
#include <utility>

namespace yuzu::server {

// Build-embedded curated map CSV (server/core/meson.build cpe_map_bundle ->
// cpe_map_bundle.cpp via embed_binary.py). Declared here so the production
// constructor can parse it without an IO dependency.
extern const std::string_view kCuratedCpeMap;

CpeIdentityResolver::CpeIdentityResolver() : CpeIdentityResolver(kCuratedCpeMap) {}

CpeIdentityResolver::CpeIdentityResolver(std::string_view curated_csv) {
    for (const CuratedRow& row : parse_curated_csv(curated_csv)) {
        // First writer wins on a duplicate key — the map is authored, dup keys
        // are an authoring error, not a runtime concern.
        map_.emplace(curated_key(row.eco, row.distro_id, row.name), Target{row.vendor, row.product});
    }
    if (map_.size() < kMinCuratedRows) {
        spdlog::critical(
            "CpeIdentityResolver: curated CPE map has {} entries, need >= {} — refusing to "
            "construct a resolver that would high-confidence-match almost nothing (fail-closed, "
            "ADR-0018)",
            map_.size(), kMinCuratedRows);
        throw std::runtime_error("curated CPE map too small: " + std::to_string(map_.size()) +
                                 " < " + std::to_string(kMinCuratedRows));
    }
}

ResolvedIdentity CpeIdentityResolver::resolve(const SoftwareEntry& e) const {
    ResolvedIdentity r;

    // 1. Lane gate FIRST — zero identity work on the not-assessed lanes.
    if (is_os_native(e)) {
        r.outcome = IdentityOutcome::NotAssessed;
        r.not_assessed_reason = std::string(kReasonOsNative);
        return r;
    }
    if (!is_lane1(e.ecosystem)) {
        r.outcome = IdentityOutcome::NotAssessed;
        r.not_assessed_reason = std::string(kReasonUnsupportedEcosystem);
        return r;
    }

    // 2. Empty name -> no derivable identity. cpe_trim_view avoids allocating a
    //    string just to test emptiness on this per-installed-software hot path.
    if (cpe_trim_view(e.name).empty()) {
        r.outcome = IdentityOutcome::NoIdentity;
        r.not_assessed_reason = std::string(kReasonNoIdentity);
        return r;
    }

    // 3. Empty version -> no version. BEFORE the map: a range test is
    //    impossible without a version, mirroring match_inventory skipping
    //    empty-version rows. A curated `openssl` with no version is NoVersion,
    //    never a High hit.
    if (cpe_trim_view(e.version).empty()) {
        r.outcome = IdentityOutcome::NoVersion;
        r.not_assessed_reason = std::string(kReasonNoVersion);
        return r;
    }

    // 4. Curated lookup, most-specific precedence:
    //    (eco, distro_id, name) -> (eco, "", name) -> ("", "", name). Three
    //    sequential early-return finds — NOT an initializer_list of the three
    //    keys, which would heap-allocate all three std::string keys on every
    //    call even when the most-specific key hits first.
    auto try_curated = [&](const std::string& key) -> bool {
        auto it = map_.find(key);
        if (it == map_.end())
            return false;
        r.outcome = IdentityOutcome::Resolved;
        r.cpe_product = it->second.product;
        r.cpe_vendor = it->second.vendor; // display/provenance ONLY (see header)
        r.exact_product = true;
        r.confidence = Confidence::High;
        return true;
    };
    if (try_curated(curated_key(e.ecosystem, e.distro_id, e.name)) ||
        try_curated(curated_key(e.ecosystem, "", e.name)) ||
        try_curated(curated_key("", "", e.name)))
        return r;

    // 5. Low-confidence normalized fallback.
    std::string n = normalize_product(e.name);
    if (n.size() < 3) {
        r.outcome = IdentityOutcome::NoIdentity;
        r.not_assessed_reason = std::string(kReasonBelowPrefixFloor);
        return r;
    }
    r.outcome = IdentityOutcome::Resolved;
    r.cpe_product = std::move(n);
    r.cpe_vendor = ""; // normalized prefix carries no vendor
    r.exact_product = false;
    r.confidence = Confidence::Low;
    return r;
}

} // namespace yuzu::server
