#include "oidc_scim_link.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/scim_store.hpp>

#include <spdlog/spdlog.h>

#include <array>
#include <utility>

namespace yuzu::server::oidc {

namespace {

/// Mirrors `OidcProvider::validate_claims`'s `sub`/`oid` rule
/// (oidc_provider.cpp) exactly: non-empty, <=255 bytes, no byte <0x20 or
/// ==0x7F. Duplicated deliberately rather than shared — `validate_claims`
/// decides whether to REJECT A LOGIN over a malformed claim (fail-closed,
/// only for the configured link claim); this decides whether a claim VALUE
/// is safe to trust into a durable observation row (a login that already
/// succeeded, evaluated for every candidate claim regardless of which one
/// is configured). Same rule, different gate.
bool is_sane_claim_value(const std::string& v) {
    constexpr std::size_t kMaxLen = 255;
    if (v.empty() || v.size() > kMaxLen)
        return false;
    for (unsigned char c : v) {
        if (c < 0x20 || c == 0x7F)
            return false;
    }
    return true;
}

void bump_link_write_failure(yuzu::MetricsRegistry* metrics) {
    if (metrics)
        metrics->counter("yuzu_scim_oidc_link_write_failures_total").increment();
}

} // namespace

void link_oidc_login_to_scim(ScimStore* scim_store, const std::string& iss, const std::string& sub,
                             const std::string& oid, const std::string& link_claim_name,
                             const std::string& link_claim_value,
                             yuzu::MetricsRegistry* metrics) {
    if (!scim_store)
        return;

    if (!link_claim_value.empty()) {
        if (auto match = scim_store->find_unique_active_by_external_id(link_claim_value)) {
            // Exactly one active match — `find_unique_active_by_external_id`
            // already folded zero AND more-than-one matches into nullopt, so
            // reaching here means the link is unambiguous.
            if (!scim_store->upsert_link(iss, sub, match->scim_id)) {
                spdlog::warn("ADR-2001: failed to persist identity link (iss={}, scim_id={}) — "
                            "login proceeds; D2 detector will surface this via the login "
                            "observation",
                            iss, match->scim_id);
                bump_link_write_failure(metrics);
            }
        }
    }

    // D2 tripwire (governance Gate 7 BLOCKING fix, the crux): record an
    // observation for EACH candidate claim that is present and sane — not
    // just `link_claim_name`/`link_claim_value` (the configured one). This
    // is what lets a later deprovision's `observation_matches(external_id)`
    // find the NON-configured candidate under a misconfigured
    // `--oidc-scim-link-claim` (see the .hpp doc comment).
    const std::array<std::pair<const char*, const std::string&>, 2> candidates{{
        {"sub", sub},
        {"oid", oid},
    }};
    for (const auto& [claim_name, claim_value] : candidates) {
        if (!is_sane_claim_value(claim_value))
            continue;
        if (!scim_store->record_login_observation(iss, sub, claim_name, claim_value)) {
            spdlog::warn("ADR-2001: failed to record OIDC login observation (iss={}, claim={})",
                        iss, claim_name);
            bump_link_write_failure(metrics);
        }
    }
}

} // namespace yuzu::server::oidc
