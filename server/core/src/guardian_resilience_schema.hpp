#pragma once

/// @file guardian_resilience_schema.hpp
///
/// Single source of truth for the Guardian per-rule **resilience policy** params
/// that live in a rule's `remediation.params` (design
/// `docs/yuzu-guardian-design-v1.1.md` §8.5; contract `docs/guardian-mvp-contract.md`
/// decisions 3/10). ONE param-spec table drives BOTH:
///   * server-side authoring validation (`validate_and_canonicalize_resilience_params`), and
///   * the published JSON Schema (`resilience_params_schema`) served by
///     `GET /api/v1/guaranteed-state/schemas`.
/// So the discovery surface and the validator can never disagree — the divergence
/// that would mislead an agent author following our own schema. (C3b.)
///
/// The agent reads the SAME keys via `parse_resilience_params()` in
/// `agents/core/include/yuzu/agent/resilience_strategy.hpp` (`resilience_keys`).
/// Production server code deliberately does **not** include that agent header —
/// there is no server→agent module dependency anywhere else, and we keep it that
/// way. Instead a cross-check unit test binds this table's key set to the agent's
/// `resilience_keys`, so a rename on either side fails the test gate (the
/// schema↔handler drift mitigation contract G9 prescribes).

#include <nlohmann/json_fwd.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::guardian {

/// A resilience-param validation failure. `remediation` is an agent-actionable
/// hint surfaced in the A4 error envelope so an agentic author self-corrects.
struct ResilienceParamError {
    std::string message;
    std::string remediation;
};

/// Validate the resilience policy keys inside a `remediation.params` object and
/// canonicalise them in place: `mode` → lowercase token; numeric keys → decimal
/// string (the string form the agent's `parse_resilience_params` and the
/// push-builder marshal onto the wire). Lenient-in / canonical-out (contract
/// decision 3):
///   * only the chosen mode's **load-bearing** params are range-checked — a param
///     present but irrelevant to the mode (e.g. `backoff_initial_ms` on a Persist
///     rule) is passed through untouched, never a 400;
///   * unknown keys (other remediation params) are ignored.
/// `params` may be any JSON value; a non-object is treated as "no resilience
/// params" and accepted. Returns `nullopt` when valid, else the first error.
std::optional<ResilienceParamError>
validate_and_canonicalize_resilience_params(nlohmann::json& params);

/// JSON Schema (draft 2020-12) for the resilience policy params, derived from the
/// same param-spec table the validator uses. Embedded under the remediation type
/// schemas served by `GET /schemas`. Pure; no I/O.
nlohmann::json resilience_params_schema();

/// The canonical resilience param key names (this table's keys), sorted. Exposed
/// for the cross-check unit test that asserts equality with the agent's
/// `resilience_keys`. Not needed by production callers.
std::vector<std::string_view> resilience_param_keys();

} // namespace yuzu::server::guardian
