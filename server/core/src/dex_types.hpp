#pragma once

/// @file dex_types.hpp
/// PURE value types for the DEX (Digital Employee Experience) family — the
/// leaf read-model PODs shared across the store, the read-model builders, the
/// dashboard fragments, and the in-process `DexApi` seam (ADR-0031 WS-A4).
///
/// This header is store-free and httplib-free BY CONSTRUCTION: only `<cstdint>`
/// / `<string>` / `<vector>` / `<utility>`. It exists so the abstract
/// `dex_api.hpp` (and the pure `dex_read_model.hpp`) can name these types
/// without dragging in `guaranteed_state_store.hpp` (a CATASTROPHIC
/// Guardian/Guaranteed-State store header) or `dex_routes.hpp` (which pulls
/// `<httplib.h>`). Those two headers now `#include` THIS one and keep re-
/// exporting these types transitively, so every existing includer is
/// unaffected (ODR-safe relocation, not a duplication).
///
/// Two groups live here:
///   1. The DEX read-model aggregations over `guardian_observations`
///      (relocated verbatim from `guaranteed_state_store.hpp`).
///   2. `DexFleet` / `DexSignalGroup` — the cross-store fleet denominator and
///      the display-family descriptor (relocated verbatim from
///      `dex_routes.hpp`; both are pure PODs the store header never needed).

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

// ── One captured Guardian observation (the raw event journal projection) ─────
struct GuardianObservationRow {
    std::string event_id;          // shares the event journal dedup key
    std::string agent_id;
    std::string observed_at;       // ISO-8601 (= event timestamp)
    std::string obs_type;          // = event_type, e.g. "process.crashed", "os.boot"
    std::string subject;           // e.g. "notepad.exe", "Spooler", "HP LaserJet"
    std::string reason;            // e.g. "0xC0000005", "0x80070643", "timeout"
    std::string symbolic;          // e.g. "ACCESS_VIOLATION", "WIFI_DISCONNECT"
    std::string component;         // e.g. "ntdll.dll" (faulting module)
    std::string version;           // crashed/hung app's file version "a.b.c.d", "" if unknown
    double metric{0.0};            // numeric payload (boot duration ms); 0 = none
    std::string platform;          // "windows" | "linux" | "macos"
};

// ── DEX read-model aggregations over guardian_observations ───────────────────
struct DexCrashSummary {
    int64_t total_crashes{0};
    int64_t distinct_devices{0};   // devices impacted (crash-free numerator)
    int64_t distinct_apps{0};
};
struct DexAppCrashCount {          // top unreliable apps + blast radius
    std::string subject;           // process name
    std::string version;           // app file version, "" = unknown/all (version-blind query)
    int64_t crashes{0};
    int64_t hangs{0};
    int64_t distinct_devices{0};   // blast radius = distinct devices, not event count
    std::string last_seen;
};
struct DexModuleCrashCount {       // top faulting modules (crash-scoped)
    std::string component;         // module name
    int64_t crashes{0};
    int64_t distinct_apps{0};
};
struct DexDeviceCrashCount {       // most-affected devices (crash-scoped)
    std::string agent_id;
    int64_t crashes{0};
    std::string last_seen;
};
struct DexOsCrashCount {           // per-OS split (coverage-normalised at the route)
    std::string platform;
    int64_t crashes{0};
    int64_t distinct_devices{0};
};
struct DexDayCrashCount {          // crashes-per-day trend
    std::string day;               // YYYY-MM-DD
    int64_t crashes{0};
};
struct DexExceptionCount {         // top failure reasons (per-app drill-down)
    std::string reason;            // e.g. "0xC0000005"
    std::string symbolic;          // e.g. "ACCESS_VIOLATION"
    int64_t crashes{0};
};
struct DexEntitySummary {          // per-app / per-device drill-down summary
    int64_t crashes{0};
    int64_t hangs{0};
    int64_t signals{0};            // ALL observation rows for the entity (any type)
    int64_t distinct_devices{0};
    int64_t distinct_apps{0};
    std::string first_seen;
    std::string last_seen;
};
struct DexSignalCount {            // the whole-catalogue rollup (overview panel)
    std::string obs_type;
    int64_t count{0};
    int64_t distinct_devices{0};
    std::string last_seen;
};
struct DexSubjectCount {           // top subjects for ONE obs_type (signal drill-down)
    std::string subject;
    int64_t count{0};
    int64_t distinct_devices{0};
    std::string last_seen;
};
struct DexOsScope {                // per-OS coverage: how many types each OS collects
    std::string platform;
    int64_t distinct_types{0};
    int64_t total_events{0};
};
struct DexDaySignal {              // one (day, obs_type) cell of the trends matrix
    std::string day;               // YYYY-MM-DD
    std::string obs_type;
    int64_t count{0};
};
struct DexBootStats {              // boot-performance rollup (os.boot metric, ms)
    int64_t boots{0};
    double avg_ms{0.0};
    double max_ms{0.0};
    int64_t distinct_devices{0};
};
struct DexDeviceBoot {             // slowest-booting devices
    std::string agent_id;
    double avg_ms{0.0};
    double max_ms{0.0};
    int64_t boots{0};
};

// ── Cross-store fleet denominator + display-family descriptor ────────────────

/// Fleet-size denominator for the DEX rates — sourced cross-store from the agent
/// registry (NOT the crash store). `windows_online` remains the established
/// headline crash-rate denominator (and the "all" catalogue lens's denominator,
/// kept for continuity); macOS and Linux crash/reliability collectors now exist
/// too, and the per-OS counters below denominate the catalogue's single-OS
/// lenses. `total_online` is context. A struct (not a registry dep) keeps
/// render pure + testable.
struct DexFleet {
    int64_t windows_online{0};
    int64_t total_online{0};
    /// Distinct OS tokens (lowercased: "windows"/"linux"/"darwin") of the agents
    /// CONNECTED right now — the coverage scope for the Catalogue's "All connected"
    /// lens. Empty when nothing is connected.
    std::vector<std::string> connected_os;
    /// CONNECTED agents as (agent_id, normalized-os: "windows"/"linux"/"macos").
    /// The Overview computes a per-device DEX score for each (window-respecting) to
    /// build the experience distribution AND groups by os for the segment breakdown.
    /// Kept here (not pre-scored) so only the Overview pays the per-device cost.
    std::vector<std::pair<std::string, std::string>> connected_agents;
    /// Per-OS online-agent denominators (#1746) — the same coverage-honest count as
    /// windows_online, split by platform, so the Catalogue's single-OS filter can
    /// score a family against THAT OS's own online count instead of borrowing
    /// windows_online. APPENDED here (not alongside windows_online) so the many
    /// positional aggregate initializers of this struct across the test suite keep
    /// compiling unchanged — trailing members default-init to 0.
    int64_t linux_online{0};
    int64_t macos_online{0};
};

/// One display family of the server-side signal catalogue. PUBLIC since F1:
/// the Settings → DEX alerts panel renders the routable-type list from this
/// same single source of truth (the /dex Catalogue's grouping).
struct DexSignalGroup {
    const char* name;
    std::vector<const char*> types;
};

} // namespace yuzu::server
