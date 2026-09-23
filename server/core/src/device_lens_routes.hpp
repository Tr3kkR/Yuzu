#pragma once

/// @file device_lens_routes.hpp
/// The DEX + Guardian LENS fragments for the shared device page
/// (`/fragments/device/dex`, `/fragments/device/guardian`) — split out of
/// `device_routes.cpp` by ADR-0031 WS-A4 (family=`device`, wave 2) so the
/// device family's enforced TUs (`device_routes.cpp`/`device_ui.cpp`) can
/// drop `GuaranteedStateStore*` and become store-free.
///
/// **DELIBERATELY OUTSIDE the seam-closure enforced set
/// (`scripts/ci/check-seam-closure.py`'s `device` family).** This is NOT the
/// `policy_admin_routes.hpp` precedent (mutators with no public REST/MCP
/// twin) — the reason here is different: these two fragments render the DEX
/// and Guardian FAMILIES' own data (per-device signal summary / per-guard
/// compliance state), which belong behind a FUTURE `DexApi`/`GuardianApi`
/// seam of their own, not the `device` family's `DeviceApi` (whose method
/// set is deliberately narrow — `list_devices`/`lookup_device` only, mirroring
/// the public `GET /api/v1/devices[/{id}]` resource). Folding DEX/Guardian
/// reads into `DeviceApi` would widen that seam past its own 1:1
/// method-per-public-resource contract (INV-31-4). Both `DexApi` (5th
/// family) and `GuardianApi` (9th family) have since landed, but this file
/// is STILL deliberately unrewired onto either — the original "until DEX/
/// Guardian get their own seam" framing is stale now that both exist; the
/// live reason is that rewiring a lens fragment onto its family's seam is
/// its OWN change, tracked separately per family (DEX: ISSUE #4576;
/// Guardian: same deferral, disclosed in the `guardian` family's own
/// landing) rather than a side effect of the seam merging. Until each
/// fragment is actually rewired, this file keeps direct
/// `GuaranteedStateStore*` access — exactly the access `device_routes.cpp`
/// had before this split, just moved.
///
/// See the "Device pages" routed-concern row (`.claude/routed-concerns.md`)
/// for the shared invariants this file must preserve verbatim: the per-lens
/// `GuaranteedState:Read` SCOPED gate (tier + management group, ancestor-
/// aware), and the `dex.device.view`/`guardian.device.view`
/// `emit_behavioral_audit` calls (behavioural-PII access audit, dashboard
/// set-and-proceed posture — a dropped/throwing audit_fn flags
/// `Sec-Audit-Failed` but still renders the fragment).

#include "device_routes.hpp" // DeviceGuardRow, render_device_dex_lens/render_device_guardian_lens/
                              // render_device_lens_placeholder, DeviceRoutes::ScopedPermFn

#include <httplib.h>

#include <functional>
#include <string>

namespace yuzu::server {

class HttpRouteSink;
class GuaranteedStateStore;

/// `/fragments/device/dex` + `/fragments/device/guardian` — the DEX/Guardian
/// lens fragments for the shared device page. See the file banner above for
/// why this stays outside the `device` family's seam-closure enforcement.
class DeviceLensRoutes {
public:
    using ScopedPermFn = DeviceRoutes::ScopedPermFn;
    using AuditFn = DeviceRoutes::AuditFn;

    /// `store` backs both lenses (nullptr → an honest "store unavailable"
    /// placeholder, matching device_routes.cpp's pre-split posture exactly);
    /// `scoped_perm_fn`/`audit_fn` are the same per-device gate + behavioural-
    /// PII audit chokepoints every other per-device device-page route uses.
    void register_routes(httplib::Server& svr, ScopedPermFn scoped_perm_fn,
                         const GuaranteedStateStore* store, AuditFn audit_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no
    /// httplib acceptor, the #438 TSan trap). The httplib::Server& overload
    /// wraps + delegates.
    void register_routes(HttpRouteSink& sink, ScopedPermFn scoped_perm_fn,
                         const GuaranteedStateStore* store, AuditFn audit_fn = {});

private:
    ScopedPermFn scoped_perm_fn_;
    const GuaranteedStateStore* store_ = nullptr;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
