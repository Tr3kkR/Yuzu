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
/// AUTH: the `/devices` + `/device` page shells are auth-only chrome (they carry no
/// fleet data — only a title + the fragment URL to load), matching the sibling
/// `/dex` shell. The DATA-bearing routes are gated like `/api/agents`:
///   * the fleet LIST (`/fragments/devices/list`) requires global Infrastructure:Read
///     (`perm_fn`) and is sourced from the per-operator-SCOPED provider
///     (`get_visible_agents_json` in server.cpp) — exact parity with `/api/agents`;
///   * every PER-DEVICE route (page/info + the DEX/Guardian lenses + the live pull)
///     gates on `scoped_perm_fn` = `require_scoped_permission(<securable>,<op>,id)`,
///     the codebase's tier + management-group chokepoint, so an operator can only
///     open / read / live-query a device inside their management scope (a global
///     grant OR a role assigned on the device's group / an ancestor). The DEX +
///     Guardian lenses additionally audit-on-open (behavioural PII); the live pull
///     keeps its Execute probe (htmx-friendly note) on top of the scoped Read floor.

#include <yuzu/server/auth.hpp>

#include "dex_routes.hpp" // DexRoutes::DispatchFn/ResponsesFn/AuditFn + DexAgentResponse

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

/// PURE: the "Get live info" snapshot SHELL — a header + one auto-loading panel per
/// live instruction (each div hx-gets /fragments/device/live/run?kind=…, which
/// dispatches a real plugin instruction to the device and polls for the result).
/// Live = queried on the agent NOW (no 30s heartbeat wait).
std::string render_device_live_shell(const std::string& agent_id);

/// One live process row: PID + name + the SHA-256 of its on-disk image + the
/// resolved executable path (hash/path empty when unresolved).
struct LiveProcess {
    int pid = 0;
    std::string name;
    std::string sha256; ///< lowercase hex; "" if unresolved / too large / gone
    std::string path;   ///< resolved exe path; "" if unresolved
};

/// PURE: render the live `processes/list_hashed` result — a PID/name/SHA-256
/// table. The full list renders into the DOM but only the first 10 rows show;
/// a search box (gpSearchTopN) filters by name/PID/hash/path and expands matches.
std::string render_device_live_processes(const std::vector<LiveProcess>& procs);

/// PURE: render a simple key/value live result (e.g. os_info/uptime) as a tile.
std::string render_device_live_value(const std::string& label, const std::string& value);

// ── Live snapshot v2: TAR-styled collapsible cards (feat/device-live-snapshot) ──
// Each card is fed by ONE live plugin action (process_tree joins a second), parsed
// in device_routes.cpp and rendered by the typed PURE renderers below. All agent
// fields are HTML-escaped at render. Mockup: docs/mockups/device-live-snapshot.html.

/// One node of the live process tree (processes/list_tree → proc|pid|ppid|name|sha256|path).
struct LiveProcNode {
    std::uint32_t pid = 0;
    std::uint32_t ppid = 0;
    std::string name;
    std::string sha256; ///< lowercase hex; "" if unresolved
    std::string path;   ///< resolved exe path; "" if unresolved
};

/// One live TCP entry joined to a tree node by pid (network_diag/connections, Windows
/// emits the owning pid). `listening` rows have no remote endpoint.
struct LiveConn {
    std::uint32_t pid = 0;
    std::string remote_addr; ///< "" for a listener
    int remote_port = 0;
    int local_port = 0;
    bool listening = false;
};

struct LiveArpEntry { std::string iface, ip, mac, type; };
struct LiveDnsEntry { std::string name, record_type; };
struct LiveListen { std::string proto, ip; int port = 0; long long pid = 0; };
struct LiveConnRow { std::string proto, local, remote, state; };
struct LiveService { std::string name, display, status, startup; };
struct LiveUserRow { std::string user, host, logon_type, session; };
struct LiveNetAddr { std::string adapter, ip; int prefix = 0; std::string gateway; };
/// One TAR capture source's local state (tar/status → config|<src>_enabled / _live_rows).
/// `dollar`/`category` are server-side presentation metadata (the agent schema registry
/// is not linked into the server, so the source list is hand-held in device_routes.cpp;
/// only sources the agent actually reports are rendered).
struct LiveCaptureSource {
    std::string name, dollar, category;
    bool enabled = false;
    long long live_rows = -1; ///< -1 = unknown (no count reported)
};

/// PURE renderers — one `.ls-tbl`/tree per card body, dark-theme, CSP-safe.
/// render_device_live_tree reconstructs a parent→child tree from the flat node set
/// (cycle/cap guarded) and joins `conns` by pid for the inline `tt-net` summary,
/// mirroring the /tar process-tree viewer.
std::string render_device_live_tree(const std::vector<LiveProcNode>& nodes,
                                    const std::vector<LiveConn>& conns);
std::string render_device_live_arp(const std::vector<LiveArpEntry>& rows);
std::string render_device_live_dns(const std::vector<LiveDnsEntry>& rows);
std::string render_device_live_listening(const std::vector<LiveListen>& rows);
std::string render_device_live_connections(const std::vector<LiveConnRow>& rows);
std::string render_device_live_services(const std::vector<LiveService>& rows);
std::string render_device_live_users(const std::vector<LiveUserRow>& rows);
std::string render_device_live_netconfig(const std::vector<LiveNetAddr>& rows);
std::string render_device_live_capture_sources(const std::vector<LiveCaptureSource>& rows);

/// PURE: honest not-found body (unknown / never-enrolled agent_id).
std::string render_device_not_found(const std::string& agent_id);

/// `/devices` + `/device` routes — page shells + read-only HTMX fragments.
class DeviceRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;

    /// Per-device tier + management-group scope gate — wraps
    /// AuthRoutes::require_scoped_permission. Returns true (leaving `res` untouched)
    /// when the caller may perform `operation` on `securable_type` for `agent_id`
    /// (global grant OR a role assigned on the agent's management group / an
    /// ancestor); otherwise writes a 403 and returns false. The single chokepoint
    /// for every per-device device-route authz decision — never hand-roll a parallel
    /// membership scan.
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;

    /// Resolve the fleet device list VISIBLE to `username`, assembled in server.cpp
    /// from the SAME per-operator scoping path as `/api/agents`
    /// (`get_visible_agents_json`): all-when-global-Infrastructure:Read, else the
    /// caller's management-group members. Empty when no provider is wired → the
    /// list renders an honest "unavailable" placeholder.
    using DevicesFn = std::function<std::vector<DeviceRow>(const std::string& username)>;

    /// Resolve ONE device's identity row by agent_id, UNSCOPED (straight from the
    /// registry — the `get_one(id)` resolver the list scan was always meant to
    /// become). Authz is the caller's responsibility: per-device routes gate on
    /// `scoped_perm_fn` FIRST, so this is a pure post-authz row fetch. It must NOT
    /// re-apply list scoping — the list filter (`get_visible_agents`) is a flat
    /// group-member JOIN with no ancestor walk, whereas `require_scoped_permission`
    /// IS ancestor-aware; re-scoping here would wrongly 404 a device a parent-group
    /// role legitimately authorizes. Returns nullopt for an unknown/offline agent.
    using LookupFn = std::function<std::optional<DeviceRow>(const std::string& agent_id)>;

    /// The "Get live info" snapshot dispatches REAL plugin instructions to the device
    /// (Execute-gated, audited) and polls the response store — the same shared
    /// chokepoint + ResponseStore seam DexRoutes uses. Empty → live info unavailable.
    using DispatchFn = DexRoutes::DispatchFn;
    using ResponsesFn = DexRoutes::ResponsesFn;
    using AuditFn = DexRoutes::AuditFn;

    /// `store` backs the DEX/Guardian lenses; `dispatch_fn`/`responses_fn`/`audit_fn`
    /// back the live-info instruction dispatch (all borrowed/may be empty/null →
    /// graceful placeholder).
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, DevicesFn devices_fn, LookupFn lookup_fn,
                         const GuaranteedStateStore* store, DispatchFn dispatch_fn = {},
                         ResponsesFn responses_fn = {}, AuditFn audit_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, DevicesFn devices_fn, LookupFn lookup_fn,
                         const GuaranteedStateStore* store, DispatchFn dispatch_fn = {},
                         ResponsesFn responses_fn = {}, AuditFn audit_fn = {});

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    ScopedPermFn scoped_perm_fn_;
    DevicesFn devices_fn_;
    LookupFn lookup_fn_;
    const GuaranteedStateStore* store_ = nullptr;
    DispatchFn dispatch_fn_;
    ResponsesFn responses_fn_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
