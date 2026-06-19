#pragma once

#include "bundle_service.hpp" // BundleStepSpec, DispatchedStep, BundleAggregate

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// Live-query bundle — transport-agnostic orchestration (ADR-0011).
//
// One object, shared by BOTH the REST routes and the MCP tools (REST/MCP
// parity by construction — neither surface reimplements dispatch or collate;
// they are thin wrappers that bind their request context into the callbacks
// below). The orchestrator deliberately takes NO httplib / proto / session
// types so it stays unit-testable and surface-neutral.
//
// Async fan-out: `dispatch` mints one correlation id, expands the instruction
// into N ordinary plugin commands (via the injected DispatchFn — the same
// per-command dispatcher REST/MCP already use), persists the ordered
// step↔command_id map, and returns immediately. `collate` reads the responses
// back (via ResponseStore::query_by_execution on the correlation id) and groups
// them against that map. The agent is unchanged — it only sees ordinary commands.
//
// STORAGE (ADR-0011): the manifest map below is IN-MEMORY (+ TTL) for v1. This
// is a deliberate v1 simplification with a COMMITTED migration target — the
// manifest MUST move to a durable Postgres `bundles` table for high
// availability and assurance (a mid-bundle restart currently loses in-flight
// manifests). See ADR-0011 "Future — durable manifest in Postgres (committed,
// not optional)". Do not let this in-memory store calcify.

namespace yuzu::server {

class ResponseStore; // collate reads responses by correlation id

class BundleOrchestrator {
public:
    /// Per-command dispatcher — the SAME shape REST/MCP already use:
    /// returns {command_id, agents_reached}. agents_reached == 0 means the
    /// command did not reach any agent (offline) → that step is dispatch-failed.
    using DispatchFn = std::function<std::pair<std::string, int>(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope,
        const std::unordered_map<std::string, std::string>& params,
        const std::string& correlation_id)>;

    /// Per-step audit sink, request-bound by the wrapper (so the core stays
    /// req-free). Called once per step with a transport-agnostic verb.
    using AuditSink = std::function<void(const std::string& verb, const std::string& result,
                                         const std::string& target_type,
                                         const std::string& target_id, const std::string& detail)>;

    /// Mints the random component of ids (hex). Injected for testability.
    using IdMinter = std::function<std::string()>;

    BundleOrchestrator(DispatchFn dispatch, ResponseStore* response_store, IdMinter mint);

    struct DispatchResult {
        std::string correlation_id;
        std::size_t expected{0};
    };

    /// Fan one instruction out into N ordinary commands on `agent_id`. Mints a
    /// `bundle-…` correlation id, dispatches each step under it, records the
    /// step↔command_id map (with per-step dispatch outcome), audits each step,
    /// and returns immediately. `principal` owns the bundle (collate checks it).
    DispatchResult dispatch(const std::string& agent_id, const std::vector<BundleStepSpec>& steps,
                            const std::string& principal, const AuditSink& audit);

    /// Collate the bundle's responses. Returns nullopt when the correlation id
    /// is unknown/expired OR not owned by `principal` (and not `is_admin`) — the
    /// caller maps nullopt to a 404 so existence isn't an enumeration oracle;
    /// the real reason is audited by the wrapper.
    [[nodiscard]] std::optional<BundleAggregate>
    collate(const std::string& correlation_id, const std::string& principal, bool is_admin);

    /// Correlation-id prefix. `notify_exec_tracker` skips ids with this prefix
    /// (mirroring the `polchk-` guard) because a bundle is NOT a tracker
    /// execution — see ADR-0011.
    static constexpr const char* kCorrelationPrefix = "bundle-";

private:
    struct Manifest {
        std::vector<DispatchedStep> steps; // ordered; command_id empty ⇒ dispatch-failed
        std::string dispatched_by;
        std::string agent_id;
        std::int64_t created_at_ms{0};
    };

    void evict_expired_locked(std::int64_t now_ms); // caller holds mu_

    DispatchFn dispatch_;
    ResponseStore* response_store_;
    IdMinter mint_;

    std::mutex mu_;
    std::unordered_map<std::string, Manifest> manifests_;

    // TTL doubles as the abandoned-bundle sweep; a generous window for a caller
    // to finish polling. Cap bounds the in-memory footprint.
    static constexpr std::int64_t kManifestTtlMs = 10 * 60 * 1000; // 10 min
    static constexpr std::size_t kMaxManifests = 4096;
};

} // namespace yuzu::server
