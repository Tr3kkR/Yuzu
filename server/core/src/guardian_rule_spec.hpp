#pragma once

/// @file guardian_rule_spec.hpp
///
/// Derivation of a Guardian Guard's canonical structured spec from a REST
/// create/update JSON body — shared by the `POST` and `PUT`
/// `/api/v1/guaranteed-state/rules` handlers so an update can re-author a Guard
/// instead of silently dropping the structured blocks (contract
/// `docs/guardian-mvp-contract.md` §8 "structured create/update"). Folds in the
/// C3b resilience-policy validation (`guardian_resilience_schema.hpp`).
///
/// Lives in its own TU so the `nlohmann::json` construction stays out of
/// `rest_api_v1.cpp` (which keeps nlohmann for request *parsing* only — building
/// response/spec JSON there triggered the template-instantiation blow-up noted at
/// the top of that file). The handler passes the already-parsed body in and gets
/// canonical strings back.

#include "guardian_resilience_schema.hpp" // ResilienceParamError

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::server::guardian {

/// Outcome of deriving a structured spec from a request body.
struct RuleSpecResult {
    /// Set → reject the request (HTTP 400, A4 envelope). Covers a resilience
    /// validation failure AND an incomplete structured body (some but not all of
    /// spark/assertion present) — the latter would otherwise silently no-op.
    std::optional<ResilienceParamError> error;
    /// True when a full spark+assertion spec was derived. False = legacy /
    /// metadata-only body; the caller keeps `yaml_source` / the existing spec.
    bool structured = false;
    /// Canonical structured spec (authoritative form); set iff `structured`.
    std::string spec_json;
    /// Generated human-readable rendering; set iff `structured`.
    std::string yaml_source;
};

/// Derive the canonical structured spec from a create/update body, validating +
/// canonicalising the `remediation.params` resilience policy. Identity/meta
/// fields are passed in (already parsed by the caller). A body carrying none of
/// spark/assertion/remediation returns `structured=false` with no error (legacy /
/// metadata-only). A body carrying some structured block but lacking a complete
/// spark+assertion pair returns an `error` rather than silently dropping it.
RuleSpecResult derive_rule_spec(const nlohmann::json& body, const std::string& name,
                                std::int64_t version, bool enabled,
                                const std::string& enforcement_mode);

/// Non-empty human-readable class name iff an ENFORCE-mode registry write at
/// `key` would land on a high-blast-radius persistence / privilege key (contract
/// §6 denylist, H1); empty = allowed. The key is canonicalised first (lowercased,
/// `/`→`\`, repeated separators collapsed, and a single leading `\` prepended so
/// the separator-anchored tokens match at string start) so a case/separator/
/// doubled-separator variant cannot dodge the substring match.
///
/// Exposed because a rule can reach enforce mode via THREE paths — structured
/// create/update, the REST metadata-only update, and the dashboard mode toggle —
/// and the create-time validator covers only the first. Every path that promotes
/// a rule to enforce (and the push boundary itself) must share this one check, or
/// the create-only gate is trivially bypassed.
std::string dangerous_enforce_registry_key(std::string_view key);

/// Non-empty human-readable class name iff ENFORCE-mode STOPPING the named service
/// would disable a security control (Defender / Security Center / Firewall / Event
/// Log) or the Yuzu agent's own service (self-destruct / flap); empty = allowed.
/// The service-control analogue of `dangerous_enforce_registry_key`: enforce
/// `service-stopped` is the dangerous direction; enforce `service-running` is
/// protective and never gated. Match is case-insensitive EXACT on the SCM key name
/// (service names are not path-structured, so substring matching would over-block).
/// Audit-mode observation of these services is always allowed.
std::string dangerous_enforce_service_stop(std::string_view service_name);

/// Parse a canonical `spec_json` and return a non-empty reason iff promoting it to
/// enforce is dangerous — a `registry-value-equals` assertion on a denylisted key,
/// or a `service-stopped` assertion on a denylisted service. Empty = safe. For the
/// callers that hold only the stored spec (the mode toggle, the metadata-only
/// update, and the push backstop), not a fresh request body — every path that
/// promotes a rule to enforce must share this one check.
std::string dangerous_enforce_in_spec(const std::string& spec_json);

} // namespace yuzu::server::guardian
