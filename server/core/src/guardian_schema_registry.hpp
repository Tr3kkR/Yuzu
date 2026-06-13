#pragma once

/// @file guardian_schema_registry.hpp
///
/// Static C++ schema registry for Guardian Guard authoring (contract
/// `docs/guardian-mvp-contract.md` G9). A type exists only if the agent compiles
/// a handler for it, so the catalog is code-coupled and static — a DB-backed
/// registry buys nothing. Exposed via `GET /api/v1/guaranteed-state/schemas` and
/// (later) an MCP resource; it is an agentic-first discovery surface (A1/A2), the
/// dashboard is one consumer.
///
/// The catalog is `{kind, type, title, json_schema}` per Slice-A type, with the
/// remediation params drawing the resilience subschema from
/// `guardian_resilience_schema.hpp` (the single source the validator also uses).
/// Built once and cached with a content-hash ETag so the response is cacheable
/// (NFR-kind / fetch-once). All `nlohmann::json` construction stays in this TU —
/// `rest_api_v1.cpp` only ever sees the serialised string.

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::guardian {

/// The serialised schema catalog plus a content-derived ETag for caching.
struct SchemaCatalog {
    std::string json; ///< serialised JSON body
    std::string etag; ///< strong ETag, e.g. "\"<hex>\"" — changes iff `json` changes
};

/// The catalog, built once on first call (static local) and cached. Pure after
/// construction; safe to share by const reference across request handlers.
const SchemaCatalog& guardian_schema_catalog();

/// Registry hive / value-type tokens the agent's RegistryGuard can actually read
/// and write (agent source: `registry_support::kHives` / `kValueTypes` in
/// `agents/core/include/yuzu/agent/guard_registry.hpp`). ONE server-side source
/// for: the published JSON-Schema enums (registry-value-equals), the authoring
/// validator (`guardian_rule_spec.cpp` `derive_rule_spec`), and any other server
/// surface. Publishing a hive/type the agent can't decode produces a guard that
/// reports perpetual false `drift.detected` (audit) or perpetual
/// `remediation.failed` (enforce) — the "confidently-wrong guard" failure mode
/// H2 closes. A cross-check unit test binds these to the agent constants so the
/// two sets can never drift apart again (contract G9 schema↔handler guard).
const std::vector<std::string_view>& supported_registry_hives();
const std::vector<std::string_view>& supported_registry_value_types();

/// Service run-state tokens the agent's ServiceGuard can actually arm and enforce
/// (agent source: `service_support::kStates` in
/// `agents/core/include/yuzu/agent/guard_service.hpp`). Each token `S` corresponds
/// to a published `service-<S>` assertion and an agent handler in
/// `guardian_engine.cpp`'s service spark branch. Same H2/G9 contract as the
/// registry accessors: a cross-check unit test binds this to the agent constant so
/// the server can never publish a `service-*` assertion the agent never arms.
/// `service-disabled` is deliberately absent (start-type config; registry-
/// expressible today, no agent handler yet).
const std::vector<std::string_view>& supported_service_states();

} // namespace yuzu::server::guardian
