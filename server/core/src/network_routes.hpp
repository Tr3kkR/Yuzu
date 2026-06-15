#pragma once

/// @file network_routes.hpp
/// Dedicated /network dashboard — the NETWORK-QUALITY lens (per-connection
/// RTT / retransmit / loss / throughput) plus the net/device/app LOCALIZATION
/// evidence. NOT an NPM clone: the leapfrog is correlation against the device
/// perf + process/service data already in the edge warehouse, which a
/// network-only tool structurally cannot do. v1 surfaces EVIDENCE + measured
/// co-occurrence; the causal verdict is a post-v1 overlay (the edge ships
/// facts, never a verdict).
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only
/// (CSP blocks hx-on). Reuses the shared full-page shell
/// (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*` component CSS —
/// same chrome as the Guardian/DEX detail pages. Read-only; the data-bearing
/// fragments gate on GuaranteedState:Read (same securable as the Guardian/DEX
/// read surface — a dedicated Network:Read perm is deferred).

#include <yuzu/server/auth.hpp>

#include "network_perf_model.hpp"

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class HttpRouteSink;

/// Shared /network sub-nav (Overview · Devices). htmx core attrs into the page
/// mount (#guardian-detail) — CSP-safe (no hx-on).
std::string network_subnav(const std::string& active);

/// PURE: the /fragments/network/overview content — fleet-now quality cards
/// (the same stats as the yuzu_fleet_net_* gauges, via the shared
/// network_perf_rules) + the co-occurrence headline (network/device/app,
/// counted never blamed) + the worst-devices drill. Every aggregate carries
/// its reporting population; RTT carries its own (smaller) denominator.
std::string render_network_overview_fragment(const NetPerfSnapshot& snap);

/// PURE: the /fragments/network/devices drill — the ONE device list serving
/// every /network drill (worst-by-metric / co-occurrence band / not-reporting /
/// cohort). Rows carry the co-occurring facts (device/app flags) inline and
/// link to the per-device drill-down.
std::string render_network_devices_fragment(const NetPerfSnapshot& snap, NetPerfMetric metric,
                                            bool not_reporting, NetCoocFilter cooc,
                                            const std::optional<std::string>& cohort_filter,
                                            int limit);

/// /network routes — /network (page shell) + the read-only HTMX fragments.
class NetworkRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;

    /// Resolve the fleet network snapshot for a cohort tag key (assembled in
    /// server.cpp from AgentHealthStore + AgentRegistry + TagStore + the DEX
    /// store). May be empty → the fragments render an honest "unavailable"
    /// placeholder (the slice-2 state, before the provider is wired).
    using PerfFn = NetPerfFn;

    /// Register the /network routes. The page shell is auth-only static chrome;
    /// the data-bearing fragments gate on GuaranteedState:Read.
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, PerfFn perf_fn = {});

    /// HttpRouteSink overload — same registration against the polymorphic seam
    /// so the handlers are unit-testable in-process via TestRouteSink (no
    /// httplib acceptor; the #438 TSan trap). The httplib::Server& overload
    /// wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, PerfFn perf_fn = {});

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    PerfFn perf_fn_;
};

} // namespace yuzu::server
