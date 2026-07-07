#pragma once

/// @file sle_routes.hpp
/// SLE (Software Licensing & Entitlements, ADR-0024) REST read surface —
/// `/api/v1/sle/*`. PR1a ships the four Decision-3.5 READ endpoints, the gate,
/// and the audit posture; the SLE page (UI), the MCP tools, and the compliance
/// evaluator that populates the posture rollup are PR1b.
///
/// Provider closures are injected (store-decoupled) so every handler is
/// unit-testable in-process via TestRouteSink without a live Postgres — the
/// InventoryRoutes / DexRoutes precedent (the #438 TSan trap). server.cpp binds
/// the closures to `SoftwareLicensingStore` (+ `ProductRegistryStore`).
///
/// AUTH (ADR-0024 Decision 9/10, roadmap D-4/D-9/G-1/G-2):
///   * `/sle/summary`, `/sle/licenses` — FLEET-WIDE aggregates built from the
///     precomputed posture rollup; exactly like the `/inventory` `software_catalog`
///     twin they cannot admit-then-filter, so they are **pinned global-only**:
///     gated on the GLOBAL `SoftwareLicensing:Read` (`perm_fn`, which resolves a
///     global grant via `check_permission`). A management-group-confined principal
///     holds only a group-scoped grant, so the global check denies them (403) —
///     never a partial/leaky rollup (ADR-0017 honesty).
///   * `/sle/licenses/{key}/devices` — the true FAN-OUT list read: global-gated NOW
///     and registered as an ADR-0017 PR-A flip-wave consumer (#1634 umbrella, #1715
///     deny-precedence prerequisite). The admit-then-filter chokepoint + its
///     "filters before LIMIT" test land at the flip, NOT here.
///   * `/sle/agents/{agent_id}` — the single-agent DRILL: takes the working
///     ancestor-aware per-device scoped gate day one (`scoped_perm_fn`, the
///     `device_routes` precedent — tier + management group, 403 outside scope),
///     because it is also Decision 11's privacy-verification surface. It renders
///     `user_scope`/`user_ref` (personal data, ADR-0024 Decision 11), so it joins
///     the per-open behavioural-audit tier (`emit_behavioral_audit`, the
///     `dex.device.view` convention) and FAILS CLOSED (503 + `Sec-Audit-Failed`)
///     when the access-audit row cannot persist.
///
/// FAIL-CLOSED GATE (roadmap G-1 / ADR-0024 Decision 10): server.cpp builds
/// `perm_fn`/`scoped_perm_fn` on the `rbac_enforcement_in_effect()` primitive,
/// NOT the raw `is_rbac_enabled()` shape whose corrupt-rbac.db fall-through to a
/// legacy-open Read is the #1717 fail-open. This class only calls the injected
/// closures; the fail-closed wiring lives at the server.cpp call site.
///
/// DEGRADE ≠ EMPTY (ADR-0024 Decision 4): every provider returns `std::nullopt`
/// on a store/pool/query degrade → the route answers 503 (A4 envelope, retryable),
/// NEVER a silent empty 200 — an empty compliance surface reads as "nothing
/// detected / nothing lapsed", the fail-open lie the store contract forbids.

#include "software_licensing_store.hpp" // LicensePostureRow / AgentLicenseRow

#include <httplib.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

/// One row of the `/sle/licenses/{key}/devices` fan-out list — which devices
/// carry a detected licence for a product key, with the device's effective
/// state and expiry. A route-level DTO (NOT a store type): the per-device
/// posture breakdown this fans out is populated by the PR1b compliance
/// evaluator, so PR1a wires a provider that returns an honest empty list.
struct SleLicenseDeviceRow {
    std::string agent_id;
    std::string hostname;
    std::string state;         ///< effective licence state (closed §3.2 vocabulary)
    std::int64_t expiry_at{0}; ///< agent-observed expiry epoch; 0 = none
};

/// `/api/v1/sle/*` read routes. Providers are injected closures; see the file
/// header for the per-route auth posture.
class SleRoutes {
public:
    /// GLOBAL securable gate (resolves auth + a GLOBAL grant; writes 401/403/503).
    /// server.cpp wires this on `rbac_enforcement_in_effect` (fail-closed, G-1).
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;

    /// Per-device tier + management-group scope gate (ancestor-aware; writes
    /// 401/403/503). Wraps `require_scoped_permission`; wired fail-closed (G-1).
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;

    /// The precomputed posture rollup (the `/sle/summary` aggregate + the
    /// `/sle/licenses` rows). `std::nullopt` on a store degrade (→ 503, never a
    /// fabricated empty). Empty vector = never evaluated yet OR a genuinely empty
    /// estate (in PR1a: always empty — the PR1b evaluator populates it).
    using PostureFn = std::function<std::optional<std::vector<LicensePostureRow>>()>;

    /// The `/sle/licenses/{key}/devices` fan-out: devices carrying `product_key`,
    /// capped at `limit`. `std::nullopt` on a degrade. server.cpp wires the PR1a
    /// provider to an honest empty list (the per-device breakdown lands in PR1b).
    using LicenseDevicesFn = std::function<std::optional<std::vector<SleLicenseDeviceRow>>(
        const std::string& product_key, int limit)>;

    /// One agent's detected-licence rows (the `/sle/agents/{id}` drill — REAL data
    /// in PR1a via `SoftwareLicensingStore::agent_licenses`). `std::nullopt` on a
    /// degrade (→ 503). An empty value = the agent genuinely reported no licences.
    using AgentLicensesFn =
        std::function<std::optional<std::vector<AgentLicenseRow>>(const std::string& agent_id)>;

    /// who/when/what audit sink (bool = persisted; false = a persist failure OR a
    /// throwing sink, routed through the #1647 throw-safe kernel). Reused signature.
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    void register_routes(httplib::Server& svr, PermFn perm_fn, ScopedPermFn scoped_perm_fn,
                         PostureFn posture_fn, LicenseDevicesFn devices_fn,
                         AgentLicensesFn agent_licenses_fn, AuditFn audit_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, PermFn perm_fn, ScopedPermFn scoped_perm_fn,
                         PostureFn posture_fn, LicenseDevicesFn devices_fn,
                         AgentLicensesFn agent_licenses_fn, AuditFn audit_fn = {});

private:
    PermFn perm_fn_;
    ScopedPermFn scoped_perm_fn_;
    PostureFn posture_fn_;
    LicenseDevicesFn devices_fn_;
    AgentLicensesFn agent_licenses_fn_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
