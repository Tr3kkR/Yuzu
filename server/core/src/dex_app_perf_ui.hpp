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

/// One management group offered in the app-perf scope selector (id + display name
/// + member count). Sourced from `ManagementGroupStore::list_groups` via the
/// DexRoutes `GroupListFn` — a plain struct so the renderer stays pure/testable.
struct DexGroupOption {
    std::string id;
    std::string name;
    std::int64_t members{0};
};

/// PURE: the app picker — every application with retained fleet perf history, each
/// row a drill into its per-version trend. `truncated` adds the honest cap note.
std::string render_dex_app_perf_picker(const std::vector<AppPerfAppSummary>& apps, bool truncated,
                                       int window_days);

/// PURE: the per-(app,version) perf-over-time table. `versions` is the reduced
/// per-version summary (`app_perf_version_summaries` over the trend points).
/// `scope_group_id` empty = whole fleet; non-empty = the named-group rollup (the
/// suppression cells render for sub-floor points). `groups` populates the scope
/// selector; `group_floor` is shown in the suppression caption.
std::string render_dex_app_perf_trend(const std::string& app_name,
                                      const std::vector<AppPerfVersionSummary>& versions,
                                      const std::string& scope_group_id,
                                      const std::vector<DexGroupOption>& groups,
                                      std::int64_t group_floor, int window_days);

} // namespace yuzu::server
