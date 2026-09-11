#pragma once

/// @file dex_read_model.hpp
/// Shared PURE builder functions for DEX capabilities that need a REST **and**
/// MCP twin — the Rule 1 home `docs/api-twin-recipe.md` §1 describes: "REST,
/// MCP, and the HTML dashboard fragment must call the same function to build
/// the response body's data." No `httplib.h`, no `mcp_jsonrpc.hpp` — every
/// function here is callable from both `rest_api_v1.cpp` and `mcp_server.cpp`
/// with zero transport dependency, so the two JSON shapes cannot drift apart
/// by construction (the anti-pattern this file exists to avoid is documented
/// by name in the recipe: `perf_stat_json`/`stat_json`, duplicated row
/// builders in `rest_api_v1.cpp` and `mcp_server.cpp`).
///
/// #4035 (api-parity programme, #2146 Batch A) is the first consumer: the two
/// MCP-only gaps (`/fragments/device/dex`'s REST twin `GET
/// /api/v1/dex/devices/{id}`, and `/fragments/dex/device/app-perf`'s REST
/// twin `GET /api/v1/dex/devices/{id}/app-perf`) each had their JSON built
/// INLINE in the REST handler with no MCP caller — this file promotes each
/// row-building block to a named, shared function per the recipe's §8 worked
/// example (`software_deployment_row_json`), and the genuinely-new
/// REST+MCP twins from the same issue (app blast-radius, app-centric
/// stability list, catalogue-group, per-device signal history,
/// single-observation detail, health score, trends, overview) follow the
/// same shape.
///
/// `DexFleet`/`DexSignalGroup` (declared in `dex_routes.hpp`, which itself
/// pulls `<httplib.h>` for the `DexRoutes` route class) are taken by const
/// reference below and only FORWARD-declared here — this header stays
/// httplib-free per Rule 1; the .cpp implementation includes `dex_routes.hpp`
/// for their full definitions, same as `mcp_server.cpp` already does today.

#include "guaranteed_state_store.hpp" // DexSignalCount/DexSubjectCount/DexDaySignal/GuardianObservationRow -- httplib-free
#include "app_perf_daily_store.hpp"   // AppPerfDailyRow (device app-perf drill)

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace yuzu::server {

class GuaranteedStateStore;
struct DexFleet;       // dex_routes.hpp -- forward decl only, see file header
struct DexSignalGroup; // dex_routes.hpp -- forward decl only, see file header

// ── MCP-only gap #1: per-device DEX score (/fragments/device/dex, GET /api/v1/dex/devices/{id}) ──

/// The per-device DEX read model: the experience score (-1 = unavailable, no
/// store) + this device's own signal summary. Mirrors the REST handler's
/// existing shape (`rest_api_v1.cpp`'s `GET /dex/devices/{id}`) exactly — this
/// struct is what that handler now builds and what the MCP twin reuses.
struct DexDeviceScoreModel {
    std::string agent_id;
    std::string window; ///< echoes the validated "24h"|"7d"|"30d"|"all" token
    int score{-1};
    std::vector<DexSignalCount> signals;
};

/// PURE: reads `store` for `agent_id`'s DEX score + per-device signal summary
/// over `since` (the caller has already resolved `window` -> `since` via
/// `dex_iso_since(dex_window_to_days(window))`, the one shared window
/// vocabulary — see `dex_routes.hpp`). `store` may be null (degrades to
/// score=-1, empty signals) so a caller can call this unconditionally after
/// its own store-unavailable branch already returned.
DexDeviceScoreModel build_dex_device_score_model(GuaranteedStateStore* store,
                                                 const std::string& agent_id,
                                                 const std::string& window, const std::string& since);

/// Shared JSON serializer — REST (`rest_api_v1.cpp`) and MCP (`mcp_server.cpp`)
/// both call this so the two response shapes cannot drift (Rule 1). Returns a
/// JSON OBJECT body (`{"agent_id":...,"window":...,"score":...,"signals":[...]}`)
/// — callers wrap it in their own envelope (`ok_json`/`tool_result`).
/// `audit_persisted` is the MCP-only evidence-gap signal (§4 of the recipe:
/// MCP has no `Sec-Audit-Failed` header channel, so a dropped audit row is
/// surfaced in the body instead) — REST never passes `false` here since it
/// fails closed (503) before reaching this call at all; the field is omitted
/// entirely when `true` (default), matching `get_dex_signal_detail`'s
/// established shape ("absent on success — consumers key on absence").
std::string dex_device_score_json(const DexDeviceScoreModel& model, bool audit_persisted = true);

// ── MCP-only gap #2: per-device app-perf drill (/fragments/dex/device/app-perf, GET /api/v1/dex/devices/{id}/app-perf) ──

/// Shared JSON serializer for the per-device B1 app-perf drill. `rows` is
/// whatever `AppPerfProviders::device(agent_id)` already returned (both REST
/// and MCP call the SAME provider — this function only serializes, matching
/// the provider-seam shape the rest of the app-perf family already uses); an
/// empty `app_filter` means "every app" (unfiltered pass-through). Returns a
/// JSON OBJECT body (`{"agent_id":...,"app":...,"rows":[...]}`). See
/// `dex_device_score_json` above for `audit_persisted`'s contract.
std::string dex_device_app_perf_json(const std::string& agent_id, const std::string& app_filter,
                                     const std::vector<AppPerfDailyRow>& rows,
                                     bool audit_persisted = true);

// ── New twin #1: app blast-radius (/fragments/dex/app, GET /api/v1/dex/app?name=) ──

/// The per-app drill-down read model: crash/hang summary + faulting modules +
/// exception codes + the affected-device list. Mirrors
/// `render_dex_app_fragment`'s data exactly (Rule 1 refactor target).
struct DexAppModel {
    std::string process_name;
    std::string window;
    DexEntitySummary summary; ///< crashes/hangs/signals/distinct_devices/first_seen/last_seen
    std::vector<DexModuleCrashCount> modules;
    std::vector<DexExceptionCount> exceptions;
    /// Affected devices, ALREADY confined to `visible` when non-null (an
    /// out-of-scope device's id is never present — not merely filtered client
    /// side) — same admit-then-filter posture as the fragment's own loop.
    std::vector<DexDeviceCrashCount> devices;
};

/// PURE: builds the model for `process_name` over `since`. `store` may be
/// null (degrades to an empty summary). `visible`: nullptr = no confinement
/// (global Read / RBAC off); non-null = the caller's admit-then-filter set
/// (ADR-0017 `authorize_list_read` chokepoint) — mirrors the fragment's own
/// `visible` param.
DexAppModel build_dex_app_model(GuaranteedStateStore* store, const std::string& process_name,
                                const std::string& window, const std::string& since,
                                const std::set<std::string>* visible);

/// Shared JSON serializer (Rule 1). `audit_persisted` per `dex_device_score_json`'s contract.
std::string dex_app_json(const DexAppModel& model, bool audit_persisted = true);

// ── New twin #2: app-centric stability list (/fragments/dex/apps, GET /api/v1/dex/apps) ──

/// The whole-fleet apps-by-reliability list — no per-agent identity (a
/// distinct-device COUNT per app, never an agent_id), so this capability
/// carries no confinement and no audit, matching the fragment's own posture.
struct DexAppsModel {
    std::string window;
    std::vector<DexAppCrashCount> apps; ///< top 100 by the store's own ranking
};

/// PURE: builds the model over `since`. `store` may be null (empty list).
DexAppsModel build_dex_apps_model(GuaranteedStateStore* store, const std::string& window,
                                  const std::string& since);

std::string dex_apps_json(const DexAppsModel& model);

// ── New twin #3: catalogue-group / signal family (/fragments/dex/catalogue/group, GET /api/v1/dex/catalogue/group) ──

/// One catalogued type's row in a family drill-down.
struct DexCatalogueGroupTypeRow {
    std::string obs_type;
    bool monitored{false}; ///< a connected, in-scope platform collects this type
    std::string coverage_platforms; ///< comma-joined, e.g. "linux, windows"; "" when not monitored
    int64_t count{0};
    int64_t distinct_devices{0};
    std::string last_seen;
};

/// The family drill-down read model — mirrors `render_dex_catalogue_group_fragment`.
/// No per-agent identity, so no confinement/audit (aggregate exemption, same as
/// the fragment's own posture — it uses the plain global `perm_fn_`, not
/// `deny_service_scoped_`).
struct DexCatalogueGroupModel {
    std::string group_name;
    std::string os;     ///< resolved scope token: "all"|"windows"|"linux"|"macos"
    std::string window;
    int monitored_count{0};
    int total_type_count{0};
    double health_score{-1.0}; ///< -1 = suppressed (nothing monitored, or the scoped denominator is 0)
    int64_t active_events{0};
    int64_t max_signal_devices{0}; ///< largest single signal's distinct-device count (#1374, not the union)
    std::vector<DexCatalogueGroupTypeRow> types;
};

/// PURE: builds the model for `group_name` (must exactly match a
/// `dex_signal_groups()` entry). Returns `std::nullopt` for an unknown family
/// name — the caller turns that into a 404 (REST) / `kInvalidParams` (MCP),
/// same "no such family" outcome the fragment's own placeholder gives.
/// `store` may be null (degrades to an all-zero, unmonitored model — never nullopt).
std::optional<DexCatalogueGroupModel> build_dex_catalogue_group_model(
    GuaranteedStateStore* store, const std::string& group_name, const std::string& os_filter,
    const DexFleet& fleet, const std::string& window, const std::string& since);

std::string dex_catalogue_group_json(const DexCatalogueGroupModel& model);

// ── New twin #4: per-device signal history (/fragments/dex/device, GET /api/v1/dex/devices/{id}/history) ──

/// One row of a device's raw signal history. Deliberately RAW facts (no
/// pre-formatted "what happened" display string, which is HTML-fragment-only
/// presentation logic per `history_detail()` in `dex_routes.cpp`'s anonymous
/// namespace) — a machine caller derives its own summary from `subject`/
/// `reason`/`symbolic`/`metric` rather than parsing a formatted string.
struct DexDeviceHistoryRow {
    std::string event_id;
    std::string observed_at;
    std::string obs_type;
    std::string subject;
    std::string reason;
    std::string symbolic;
    std::string component;
    double metric{0.0};
};

/// Behavioral PII — every call is audit-logged (dex.device.view), same verb
/// as the score-only capability (#4035 AC: this is a deliberate verb reuse —
/// the fragment at `dex_routes.cpp:2878` already audits its OWN distinct
/// signal-history capability under this exact verb, so REST/MCP match their
/// own fragment's ground truth rather than inventing a second verb).
struct DexDeviceHistoryModel {
    std::string agent_id;
    std::string window;
    DexEntitySummary summary;
    std::vector<DexDeviceHistoryRow> history; ///< up to 100, newest first
};

/// PURE: builds the model for `agent_id` over `since`. `store` may be null
/// (degrades to an empty summary/history).
DexDeviceHistoryModel build_dex_device_history_model(GuaranteedStateStore* store,
                                                     const std::string& agent_id,
                                                     const std::string& window,
                                                     const std::string& since);

std::string dex_device_history_json(const DexDeviceHistoryModel& model,
                                    bool audit_persisted = true);

// ── New twin #5: single-observation detail (/fragments/dex/observation, GET /api/v1/dex/devices/{id}/observations?event_id=) ──

/// PURE lookup + ownership check in ONE call, mirroring the fragment's own
/// oracle-closed pattern (`dex_routes.cpp:2916`): returns `std::nullopt` both
/// when the event doesn't exist AND when it exists but belongs to a
/// DIFFERENT device than `agent_id` — the caller (already past the per-device
/// scope gate) turns either case into the SAME 404, so a guessed/foreign
/// `event_id` reveals nothing beyond what the scope gate already allowed.
std::optional<GuardianObservationRow> build_dex_observation_model(GuaranteedStateStore* store,
                                                                  const std::string& agent_id,
                                                                  const std::string& event_id);

/// Shared JSON serializer for one observation — every captured projection
/// field, same fields `render_dex_observation_fragment` lays out.
std::string dex_observation_json(const GuardianObservationRow& obs, bool audit_persisted = true);

// ── New twin #6: health score (/fragments/dex/health, GET /api/v1/dex/health) ──

struct DexHealthDeduction {
    std::string name;
    std::string severity; ///< "high"|"med"|"low"
    double deduction{0.0};
};

/// The composite-health read model — no per-agent identity (a fleet-wide
/// composite score), so no confinement/audit, matching the fragment's own
/// posture.
struct DexHealthModel {
    std::string weighting; ///< resolved preset: default|stability|productivity|security
    std::string window;
    int64_t reporting{0};      ///< N = fleet.windows_online (the scoring denominator)
    double crash_free_pct{-1.0}; ///< -1 when reporting == 0 (no fabricated number)
    int64_t total_crashes{0};
    double score{-1.0};   ///< -1 = suppressed (reporting == 0)
    std::string band;     ///< "excellent"|"good"|"fair"|"poor"; "" when suppressed
    std::vector<DexHealthDeduction> deductions; ///< catalogue order (not sorted by size)
};

/// PURE: builds the model over `since`. `store` may be null (degrades to an
/// all-suppressed model). `weighting` is normalised the same way the fragment
/// does (an off-list value resolves to "default").
DexHealthModel build_dex_health_model(GuaranteedStateStore* store, const DexFleet& fleet,
                                      const std::string& weighting, const std::string& window,
                                      const std::string& since);

std::string dex_health_json(const DexHealthModel& model);

// ── New twin #7: trends (/fragments/dex/trends, GET /api/v1/dex/trends) ──

struct DexTrendsOsCard {
    std::string platform; ///< "windows"|"macos"|"linux"
    bool live{false};     ///< a collector has reported anything in-window (or Windows always-live)
    int64_t distinct_types{0};
    int64_t total_events{0};
};

/// One signal family's per-day event counts, aligned index-for-index with the
/// model's own `days` list.
struct DexTrendsFamily {
    std::string name;
    std::vector<int64_t> counts;
    int64_t total{0};
};

/// The cross-OS + per-family trends read model — no per-agent identity, so no
/// confinement/audit, matching the fragment's own posture.
struct DexTrendsModel {
    std::string window;
    int64_t total_catalogued_types{0};
    double crash_free_pct{-1.0}; ///< Windows-only; -1 when fleet.windows_online == 0
    int64_t windows_reporting{0};
    std::vector<DexTrendsOsCard> os_cards; ///< windows, macos, linux (fixed order)
    std::vector<std::string> days;         ///< YYYY-MM-DD, ascending, from the day matrix
    std::vector<DexTrendsFamily> families; ///< dex_signal_groups() order
};

/// PURE: builds the model over `since`. `store` may be null (degrades to an
/// empty model — no days, no families).
DexTrendsModel build_dex_trends_model(GuaranteedStateStore* store, const DexFleet& fleet,
                                      const std::string& window, const std::string& since);

std::string dex_trends_json(const DexTrendsModel& model);

// ── New twin #8: overview (/fragments/dex/overview, GET /api/v1/dex/overview) ──

struct DexOverviewSegment {
    std::string os;
    int devices{0};
    int avg_experience{-1}; ///< -1 when the segment has no scoreable device
};
struct DexOverviewOsRow {
    std::string platform;
    int64_t reporting{0};       ///< Windows-only today; 0 elsewhere
    double crash_free_pct{-1.0}; ///< Windows-only; -1 elsewhere / no reporting agents
    int64_t distinct_types{0};
    int64_t total_events{0};
};
struct DexOverviewDayCrash {
    std::string day;
    int64_t crashes{0};
};

/// The fleet-overview read model — the `/dex` landing page's fleet summary.
/// `top_devices` is ALREADY confined to `visible` when non-null (an
/// out-of-scope device's id is never present), same admit-then-filter
/// posture as the fragment's own loop; every other field is a fleet
/// aggregate carrying no per-agent identity.
struct DexOverviewModel {
    std::string window;
    // Experience (per-device score distribution + Device/App/Network composite).
    int overall_experience{-1}; ///< median of scoreable connected devices; -1 = none
    int device_score{-1}, app_score{-1}, network_score{-1};
    int great{0}, fair{0}, poor{0}; ///< per-device experience bucket counts
    int64_t coverage_monitored{0}, coverage_total{0};
    std::vector<DexOverviewSegment> segments; ///< by normalised OS
    // Reliability -- measured.
    double crash_free_pct{-1.0}; ///< -1 when windows_reporting == 0
    int64_t windows_reporting{0};
    double crashes_per_1k_device_days{-1.0}; ///< -1 when undefined (no window or no reporting agents)
    int64_t total_crashes{0};
    int64_t devices_impacted{0};
    int64_t total_online{0};
    // Explore teaser figures.
    int64_t active_signal_types{0};
    double health_score{-1.0};
    int64_t os_reporting_count{0};
    // Crashes per day + top lists.
    std::vector<DexOverviewDayCrash> crashes_by_day;
    std::vector<DexAppCrashCount> top_apps;
    std::vector<DexDeviceCrashCount> top_devices; ///< confined, see struct doc
    std::vector<DexOverviewOsRow> os_table;
};

/// PURE: builds the model over `since`/`window_days`. `store` may be null
/// (degrades to an all-empty model). `visible`: same admit-then-filter
/// contract as `build_dex_app_model` above.
DexOverviewModel build_dex_overview_model(GuaranteedStateStore* store, const DexFleet& fleet,
                                          const std::string& window, int window_days,
                                          const std::string& since,
                                          const std::set<std::string>* visible);

std::string dex_overview_json(const DexOverviewModel& model, bool audit_persisted = true);

} // namespace yuzu::server
