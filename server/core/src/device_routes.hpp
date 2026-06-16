#pragma once

/// @file device_routes.hpp
/// The SHARED device surfaces: the fleet `/devices` list (find a device) and the
/// per-device `/device?id=` page (the entity, with lens tabs). Reached from any
/// dashboard across Yuzu; the device is the entity, DEX / Guardian / inventory are
/// LENSES on it (mockups: docs/mockups/devices.html + device-detail.html).
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only
/// (CSP blocks hx-on — onclick/oninput helpers instead). Reuses the shared
/// full-page shell (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*`
/// component CSS — same chrome as the Guardian/DEX/Network detail pages.
///
/// SLICE 1 (this file): the navigable shell + the DEVICE-INFO lens, sourced from
/// the live AgentRegistry (real identity + online + last-seen + tags). The DEX
/// lens (reuses render_dex_device_fragment + a per-device score — gated on the
/// parked per-device-scoring decision), the GUARDIAN lens
/// (guardian_agent_rule_status + BaselineStore), and the cross-cutting LIVE-INFO
/// pull (send_to + executions/SSE, privacy-gated) land in later slices. Those
/// lens tabs render an honest "coming in a later slice" placeholder for now.
///
/// AUTH (slice 1): the page shell + device list/info are auth-only, matching the
/// CURRENT posture (the dashboard scope-picker already shows the agent list to any
/// authed operator). A dedicated `Device:Read` RBAC securable + perm gate is a
/// hardening follow-up; the behavioural DEX lens + the live pull gate on their own
/// securables (and the works-council per-category toggle / individual-view kill
/// switch) when added. `perm_fn` is threaded now so later slices can use it.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;
class GuaranteedStateStore;

/// One row of the fleet device list / the identity of one device. SLICE 1 carries
/// only what the thin AgentInfo + registry session provide for real; richer CI /
/// DEX / Guardian columns are added by later slices (see file header).
struct DeviceRow {
    std::string agent_id;
    std::string hostname;
    std::string os;       ///< "windows" | "linux" | "darwin" | "?"
    std::string arch;     ///< "x86_64" | "arm64" | "?"
    std::string agent_version;
    std::string segment;  ///< management group / segment ("" if none) — best-effort
    std::vector<std::string> tags;
    bool online = false;          ///< has a live Subscribe stream right now
    std::string last_seen;        ///< human-ish ("now", "12m ago") or ISO; "" if unknown
    int dex_score = -1;           ///< per-device DEX experience score 0–100; -1 = n/a
};

/// PURE: the `/fragments/devices/list` table — the fleet device list, filtered by
/// the (already-applied) query/os/status the caller resolved. 400k-safe in shape:
/// the caller passes a bounded/curated row set; this only renders. `q`/`os_token`/
/// `status_token` are echoed back into the controls so the fragment is
/// self-describing on swap.
std::string render_devices_list_fragment(const std::vector<DeviceRow>& rows, const std::string& q,
                                         const std::string& os_token,
                                         const std::string& status_token, std::size_t total_online,
                                         std::size_t total_devices);

/// PURE: the `/fragments/device/info` Device-info (CI-record) lens for one device.
/// Fields not in the thin AgentInfo (hardware/serial/owner/MAC) are deliberately
/// NOT fabricated here — they arrive with the inventory slice.
std::string render_device_info_fragment(const DeviceRow& d);

/// PURE: the per-device page body (identity bar + lens tabs + the active lens).
/// Slice 1 mounts the Device-info lens; the DEX/Guardian tabs hx-get a placeholder.
std::string render_device_page(const DeviceRow& d);

/// PURE: a lens panel that isn't built yet (DEX/Guardian in slice 1) — renders the
/// lens tab bar (so switching back works) + an honest "coming in a later slice"
/// message. `active` is the tab id ("dex" | "guardian").
std::string render_device_lens_placeholder(const std::string& active, const std::string& agent_id,
                                           const std::string& message);

/// One guard's compliance state on a device (Guardian lens row).
struct DeviceGuardRow {
    std::string name;       ///< the Guard's human name
    std::string state;      ///< "compliant" | "drifted" | "errored"
    std::string updated_at; ///< ISO of the evaluation that set it
};

/// PURE: the DEX lens for one device — the per-device score + its signal summary
/// (obs_type → count, already fetched) + a link to the full /dex device drill.
std::string render_device_dex_lens(const std::string& agent_id, int score,
                                    const std::vector<std::pair<std::string, std::int64_t>>& signals);

/// PURE: the Guardian lens for one device — compliance summary + per-guard state.
std::string render_device_guardian_lens(const std::string& agent_id,
                                        const std::vector<DeviceGuardRow>& guards);

/// One recent-event row in the live snapshot.
struct DeviceLiveEvent {
    std::string label;   ///< friendly signal label
    std::string subject; ///< failing entity
    std::string reason;  ///< failure detail
    std::string when;    ///< observed_at (ISO)
};

/// PURE: the "Get live info" snapshot panel — device state tiles (battery / uptime /
/// recent-event count, from the device's own observations) + recent events + an
/// EMBEDDED live-performance load (auto-fires the existing dispatched perf query).
/// `battery`/`uptime` are "" when unknown.
std::string render_device_live_snapshot(const std::string& agent_id, const std::string& battery,
                                        const std::string& uptime,
                                        const std::vector<DeviceLiveEvent>& events);

/// PURE: honest not-found body (unknown / never-enrolled agent_id).
std::string render_device_not_found(const std::string& agent_id);

/// `/devices` + `/device` routes — page shells + read-only HTMX fragments.
class DeviceRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;

    /// Resolve the current fleet device list from the live registry (assembled in
    /// server.cpp from AgentRegistry: all_ids + get_session + online + last-seen +
    /// tags). Empty when no provider is wired → the list renders an honest
    /// "unavailable" placeholder.
    using DevicesFn = std::function<std::vector<DeviceRow>()>;

    /// `store` (borrowed, may be null) backs the DEX + Guardian lenses (per-device
    /// score / signal summary / guard compliance). Null → those lenses degrade to a
    /// placeholder.
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, DevicesFn devices_fn,
                         const GuaranteedStateStore* store);

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, DevicesFn devices_fn,
                         const GuaranteedStateStore* store);

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    DevicesFn devices_fn_;
    const GuaranteedStateStore* store_ = nullptr;
};

} // namespace yuzu::server
