#pragma once

/// @file preflight_routes.hpp
/// The `/auto` PRE-FLIGHT page: a config section (per-check parameters +
/// thresholds) → run across a cohort → a go/no-go result AGGREGATED BY CHECK
/// (pass/fail per check, expandable to the failing devices). Interim manual
/// surface for the agentic upgrade-lifecycle; the orchestrator drives the same
/// checks + thresholds headless later. Reached at /auto by URL — deliberately NOT
/// a nav tab yet.
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx CORE attrs only (the
/// dashboard CSP blocks hx-on / unsafe-eval). Reuses the shared full-page shell
/// (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*` component CSS.
///
/// SLICE 1: live checks app(version) / os_version / arch / free-disk / reboot, with
/// ad-hoc config (entered per run, not persisted). Staged-artifact checks
/// (installer integrity / rollback / config backup) + Save-as-manifest persistence
/// arrive in later slices. Thresholds → verdict are applied server-side
/// (preflight_parse.hpp `evaluate`) as raw facts land.
///
/// AUTH / scope (IDOR-safe by construction):
///   * `/auto` shell is auth-only chrome.
///   * the config fragment gates on global Infrastructure:Read.
///   * RUN gates on global Execution:Execute (a fleet-wide dispatch). Targets =
///     `devices_fn(username) ∩ group members` (operator-visible set), so dispatch
///     only reaches in-scope devices and the aggregate only counts them.
///   * RESULT poll re-resolves the SAME visible∩group set (rows pinned → an offline
///     device stays "incomplete", never silently drops from the denominator).
/// Machine-health facts (OS/arch/reboot/disk/app-version), NOT behavioural PII →
/// the dispatch audit (`preflight.run`) is operational set-and-proceed.

#include <yuzu/server/auth.hpp>

#include "device_routes.hpp"   // DeviceRow
#include "dex_routes.hpp"      // DexRoutes::DispatchFn/AuditFn + DexAgentResponse
#include "preflight_parse.hpp" // Verdict, Bucket

#include <httplib.h>

#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

/// One check's outcome on one device (verdict + the device's actual value).
struct PreflightDeviceCheck {
    std::string key;
    std::string label;
    preflight::Verdict verdict = preflight::Verdict::kUnknown;
    std::string value; ///< display: "4.1.0", "9.4 GiB free…", "error", "" → "—"
};

/// One device's full result. `bucket` is the canonical roll-up
/// (preflight::classify_device); the summary pills + "Failed by" chips are derived
/// from the device set so they cannot disagree.
struct PreflightDeviceResult {
    std::string agent_id;
    std::string hostname;
    std::string os; ///< family: "windows" | "linux" | "darwin" | "?"
    preflight::Bucket bucket = preflight::Bucket::kIncomplete;
    std::vector<PreflightDeviceCheck> checks; ///< applicable checks, in catalogue order
};

/// PURE: the config section (scope + per-check params/thresholds + Run) and an
/// empty results container. `groups` = (id, name) for the scope dropdown.
std::string render_auto_config(const std::vector<std::pair<std::string, std::string>>& groups);

/// PURE: the result GROUPED BY DEVICE (Pass / Failed / Warn-only / Incomplete),
/// with bucket + failure-type client-side filters (CSP-safe inline JS). Summary
/// pills + "Failed by" chip counts are derived here from `devices`.
/// `config_summary` is the one-line threshold recap; `repoll_url` non-empty → the
/// wrapper self-polls (≥1 device still answering), empty → final.
std::string render_auto_results(const std::vector<PreflightDeviceResult>& devices,
                                const std::string& config_summary, const std::string& scope_label,
                                const std::string& repoll_url);

/// PURE: an honest note body (no devices in scope, missing seam, etc.).
std::string render_auto_note(const std::string& message);

/// `/auto` routes — page shell + config fragment + run dispatch + result poll.
class PreflightRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    using DevicesFn = std::function<std::vector<DeviceRow>(const std::string& username)>;
    using GroupsFn = std::function<std::vector<std::pair<std::string, std::string>>()>;
    using GroupMembersFn = std::function<std::vector<std::string>(const std::string& group_id)>;
    using DispatchFn = DexRoutes::DispatchFn;
    /// Read ALL agents' stored responses for a command_id (fleet poll). The grid
    /// only counts the pinned visible∩group devices, so an extra agent is ignored.
    using ResponsesAllFn =
        std::function<std::vector<DexAgentResponse>(const std::string& command_id)>;
    using AuditFn = DexRoutes::AuditFn;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, DevicesFn devices_fn,
                         GroupsFn groups_fn, GroupMembersFn group_members_fn, DispatchFn dispatch_fn,
                         ResponsesAllFn responses_all_fn, AuditFn audit_fn);

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    DevicesFn devices_fn_;
    GroupsFn groups_fn_;
    GroupMembersFn group_members_fn_;
    DispatchFn dispatch_fn_;
    ResponsesAllFn responses_all_fn_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
