#pragma once

/// @file dex_app_perf_ui.hpp
/// Slice-2 dashboard renderers for DEX app-perf-over-time — the app picker + the
/// per-(app,version) trend table (fleet B2 or named-group B1). PURE free functions
/// over the reduced model (`app_perf_version_summaries`), so the HTMX surface, the
/// REST endpoints, and the MCP tools all read the SAME numbers. Declared here (not
/// in the already-large dex_routes.hpp) so the renderer + its scope-selector type
/// stay a small, separately-testable unit.

#include "dex_app_perf_model.hpp" // AppPerfVersionSummary, AppPerfAppSummary (via fleet store)

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server {

/// One management group offered in the app-perf scope selector (id + display
/// name). Sourced from `ManagementGroupStore::list_groups` via the DexRoutes
/// `GroupListFn` — a plain struct so the renderer stays pure/testable. Deliberately
/// NO member count: counting per group would be an N+1 over the store on every
/// render (`list_groups` carries no count); the selector shows names only.
struct DexGroupOption {
    std::string id;
    std::string name;
};

/// PURE: the app picker — every application with retained fleet perf history, each
/// row a drill into its per-version trend. `truncated` adds the honest cap note.
std::string render_dex_app_perf_picker(const std::vector<AppPerfAppSummary>& apps, bool truncated,
                                       int window_days);

/// PURE: the per-(app,version) perf-over-time table. `versions` is the reduced
/// per-version summary (`app_perf_version_summaries` over the trend points) —
/// already narrowed to `active_version` UPSTREAM (by the caller passing `version`
/// into the same `AppPerfFleetFn`/`AppPerfGroupFn` provider the REST twin uses,
/// mirroring `GET /dex/perf/app?version=`) when one is selected; `versions` then
/// carries just that one entry. `active_version` empty (the default) = all
/// versions, unnarrowed. `scope_group_id` empty = whole fleet; non-empty = the
/// named-group rollup (the suppression cells render for sub-floor points).
/// `groups` populates the scope selector; `group_floor` is shown in the
/// suppression caption. Version filtering is click-through, not a dropdown (the
/// candidate values are exactly the rows already on screen): each version row's
/// label links to `?version=<v>`, narrowing; a filtered view shows a single row
/// plus an "All versions" link back to `?version=` cleared.
std::string render_dex_app_perf_trend(const std::string& app_name,
                                      const std::vector<AppPerfVersionSummary>& versions,
                                      const std::string& scope_group_id,
                                      const std::vector<DexGroupOption>& groups,
                                      std::int64_t group_floor, int window_days,
                                      const std::string& active_version = "");

/// PURE: the per-DEVICE app-perf drill (B1) — one application per group, its
/// versions as sub-rows, with a CPU-over-time sparkline and window aggregates.
/// Sits inline inside the device drill's perf panel (in-place swap, no back-link —
/// peer of the live procperf table, NOT the full-pane fleet picker). `apps` is the
/// reduced model (`app_perf_device_summaries`); an empty `apps` renders the honest
/// empty state (the caller already mapped a store degrade to a 503 + note). Single
/// device → exact daily values (no percentiles, no cohort floor — it is behind the
/// `dex.device.app_perf.view` audit gate). Per-version crashes/hangs are deferred
/// (a separate central crash-store join), noted in the foot.
std::string render_dex_device_app_perf(const std::vector<AppPerfDeviceApp>& apps);

} // namespace yuzu::server
