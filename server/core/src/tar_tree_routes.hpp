#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

/// @file tar_tree_routes.hpp
/// The TAR process-tree viewer route module — Frame 3 of the `/tar` dashboard page.
/// Picks ONE live host, dispatches two canned read-only `tar.sql` queries to it
/// ($Process_Live + $TCP_Live), polls the response store (the device-page "Get live
/// info" dispatch/poll seam), reconstructs a per-host process tree over a chosen
/// timescale (tar_process_tree.hpp), and renders the HTMX fragments.
///
/// Product UI: HTMX, server-rendered, dark-theme only; htmx core attrs only (CSP
/// blocks hx-on). Per-host only; data from the agent's local tar.db only.
///
/// AUTH: the frame fragment + a per-host reconstruction gate on `Infrastructure:Read`
/// SCOPED to the device. The READ tier follows the TAR page (the TAR SQL frame is also
/// `Infrastructure:Read`) — NOT the `GuaranteedState:Read` floor the device-live-info /
/// DEX-perf drills use; only the Execute-PROBE posture (soft in-panel note for a
/// read-only operator) is shared with those seams. A reconstruction additionally
/// DISPATCHES a live `tar.sql`, so /run + /result require `Execution:Execute`. The
/// reconstruction is cached under an unguessable CSPRNG token (secure_random); the
/// /detail route holds the SAME tier as the reconstruction (re-checks SCOPED Read +
/// Execute on the cached device_id) AND binds the entry to the originating principal,
/// so a predicted/leaked token can neither cross management scope, downgrade the
/// Execute tier, nor be replayed under a different session.

#include <yuzu/server/auth.hpp>

#include "dex_routes.hpp"      // DexRoutes::ResponsesFn/AuditFn + DexAgentResponse
#include "device_routes.hpp"   // DeviceRow
#include "dispatch_caller.hpp" // DispatchCaller
#include "tar_process_tree.hpp"

#include <httplib.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

/// The `/tar` interactive-fragment route controller. Despite the historical name it
/// now owns THREE operator surfaces, all sharing the same scoped-Read + Execute-probe
/// + dispatch/poll seam and the eight providers below:
///   1. Process-tree viewer   — `/fragments/tar/process-tree[/run|/result|/detail]`
///   2. Device DNS/ARP panels — `/fragments/tar/process-tree/device-net` (ADR-0015)
///   3. Capture-sources frame — `/fragments/tar/capture-sources[/load|/push]` (ADR-0015)
/// (A rename to `TarFrameRoutes` + a split of the capture-sources surface is tracked
/// as a deferred follow-up; folding them here avoids a second server.cpp registration.)
class TarTreeRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& op)>;
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& op,
                           const std::string& agent_id)>;
    /// Operator-scoped connected-device list (the host picker) — same provider the
    /// `/devices` list + scope chip use (`get_visible_agents_json`).
    using DevicesFn = std::function<std::vector<DeviceRow>(const std::string& username)>;
    /// Unscoped single-device identity lookup (for the device's OS — the Windows
    /// names-only caption). Authz is the scoped gate the routes run first.
    using LookupFn = std::function<std::optional<DeviceRow>(const std::string& agent_id)>;
    /// Review finding (external PR review, #3133): every dispatch in this class used
    /// to go through `DexRoutes::DispatchFn` (no caller parameter), which server.cpp
    /// wired to the unfiltered `command_dispatch_fn` — so a mutating action
    /// (`tar.configure`, the capture-source push) dispatched as `system`, bypassing
    /// the catalogue's `Infrastructure:Write` requirement even though the route
    /// itself only ever checked `Infrastructure:Read`. TarTreeRoutes now has its own
    /// caller-aware signature — deliberately NOT sharing `DexRoutes::DispatchFn` with
    /// `DeviceRoutes` (the device-live-info panel), whose read-only, pre-existing
    /// system dispatch is a separate, non-blocking finding from the same review.
    using DispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const yuzu::server::DispatchCaller& caller)>;
    using ResponsesFn = DexRoutes::ResponsesFn;
    using AuditFn = DexRoutes::AuditFn;
    /// Resolves the caller's identity + Execution:Execute visible set from the
    /// request — same contract as WorkflowRoutes::CallerFn: an UNWIRED callback
    /// fails CLOSED (empty principal, present-EMPTY exec_visible), never nullopt.
    using CallerFn = std::function<yuzu::server::DispatchCaller(const httplib::Request&)>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, DevicesFn devices_fn, LookupFn lookup_fn,
                         DispatchFn dispatch_fn, ResponsesFn responses_fn, AuditFn audit_fn,
                         CallerFn caller_fn);

    /// HttpRouteSink overload — in-process testable (no httplib acceptor; #438).
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, DevicesFn devices_fn, LookupFn lookup_fn,
                         DispatchFn dispatch_fn, ResponsesFn responses_fn, AuditFn audit_fn,
                         CallerFn caller_fn);

private:
    /// One cached reconstruction. Holds the rendered tree (node-id addressable by the
    /// detail route) + the host's connection set (filtered per-pid at detail time) +
    /// the device_id/os used for the per-detail scoped re-check and the names-only
    /// caption + the originating principal (the detail route fails closed unless the
    /// requesting session matches, so a predicted/leaked token can't be replayed under
    /// a different identity even within the same management scope).
    struct ReconEntry {
        std::string device_id;
        std::string principal; ///< session->username that created this reconstruction
        std::string os;
        TarProcTree tree;
        std::vector<TarTcpConn> conns;
        std::int64_t created = 0;
    };

    /// Bounded (kCacheCap) + TTL (kCacheTtlSeconds) reconstruction cache. Token is an
    /// unguessable random hex; insertion-ordered for eviction. Guarded by cache_mu_.
    /// Cap kept modest: each entry can hold up to a 50k-node tree + 5k conns, so 32 ×
    /// worst-case bounds peak cache RSS (~0.8 GB ceiling; typical trees are far smaller).
    /// NOTE (multi-server): this cache is node-local — a future multi-server deployment
    /// must NOT assume a token resolves on another node.
    static constexpr std::size_t kCacheCap = 32;
    static constexpr std::int64_t kCacheTtlSeconds = 180;

    void cache_put(const std::string& token, ReconEntry entry);
    /// Render one node's detail from the cached entry (under lock; render is cheap).
    /// nullopt → token unknown/expired. Validates node_id internally.
    std::optional<std::string> cache_render_detail(const std::string& token, std::size_t node_id,
                                                   std::string* out_device_id);

    AuthFn auth_fn_;
    PermFn perm_fn_;
    ScopedPermFn scoped_perm_fn_;
    DevicesFn devices_fn_;
    LookupFn lookup_fn_;
    DispatchFn dispatch_fn_;
    ResponsesFn responses_fn_;
    AuditFn audit_fn_;
    CallerFn caller_fn_;

    std::mutex cache_mu_;
    std::unordered_map<std::string, ReconEntry> cache_;
    std::list<std::string> cache_order_; ///< front = oldest
};

} // namespace yuzu::server
