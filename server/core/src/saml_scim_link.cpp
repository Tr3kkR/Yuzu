#include "saml_scim_link.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/scim_store.hpp>

#include <spdlog/spdlog.h>

namespace yuzu::server::saml {

namespace {

// The two NameID Format URIs this codebase treats as STABLE — see the
// header doc. `test_saml_provider.cpp`'s fixture default matches the
// emailAddress one, so the existing (pre-PR4a) test suite's default
// assertions are already linkable without modification.
constexpr const char* kPersistentFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
constexpr const char* kEmail11Format    = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

void bump_link_write_failure(yuzu::MetricsRegistry* metrics) {
    if (metrics)
        metrics->counter("yuzu_scim_saml_link_write_failures_total").increment();
}

} // namespace

bool is_linkable_name_id_format(const std::string& name_id_format) {
    return name_id_format == kPersistentFormat || name_id_format == kEmail11Format;
}

void link_saml_login_to_scim(ScimStore* scim_store, const std::string& entity_id,
                             const std::string& name_id, const std::string& name_id_format,
                             yuzu::MetricsRegistry* metrics) {
    if (!scim_store)
        return;
    if (!is_linkable_name_id_format(name_id_format))
        return; // transient/unspecified/missing — never a durable join key

    auto match = scim_store->find_unique_active_by_external_id(name_id);
    if (!match)
        return; // zero or ambiguous matches — no link, no error (ADR-2001 §2 posture)

    if (!scim_store->upsert_saml_link(entity_id, name_id, match->scim_id)) {
        spdlog::warn("ADR-2001 PR4a: failed to persist SAML identity link (entity_id={}, "
                    "scim_id={}) — login proceeds",
                    entity_id, match->scim_id);
        bump_link_write_failure(metrics);
    }
}

} // namespace yuzu::server::saml
