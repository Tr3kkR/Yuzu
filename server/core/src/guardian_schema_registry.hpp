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

namespace yuzu::server::guardian {

/// The serialised schema catalog plus a content-derived ETag for caching.
struct SchemaCatalog {
    std::string json; ///< serialised JSON body
    std::string etag; ///< strong ETag, e.g. "\"<hex>\"" — changes iff `json` changes
};

/// The catalog, built once on first call (static local) and cached. Pure after
/// construction; safe to share by const reference across request handlers.
const SchemaCatalog& guardian_schema_catalog();

} // namespace yuzu::server::guardian
