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

} // namespace yuzu::server
