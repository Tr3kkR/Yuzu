#pragma once

/// @file scim_routes.hpp
/// SCIM v2 provisioning REST surface (slice 3 of 3): `/scim/v2/*`.
///
/// Wires the storage layer (`ScimStore`, slice 1) and JSON codec (`yuzu::
/// server::scim`, slice 2) into an HTTP surface an enterprise IdP (Okta/
/// Entra) drives to auto-provision and auto-deprovision Yuzu operators.
/// Users-only in this slice — no Groups resource.
///
/// AUTH MODEL: every route (including discovery) is gated on a static Bearer
/// token validated against `ScimStore` (sha256 + constant-time compare) —
/// there is no session/cookie/CSRF surface here; the fixed audit principal
/// `"scim-service"` stands in for "there is no human operator on this path".
///
/// SECURITY INVARIANT (provenance guard): SCIM may only ever mutate an auth
/// account IT provisioned. Every deactivate/reactivate/delete re-checks
/// `AuthDB::get_provisioning_source(username) == "scim"` immediately before
/// calling into `AuthManager` — see `scim_routes.cpp`'s `provenance_ok`. A
/// mismatch (including a locally-created admin, which has no `provisioning_
/// source == "scim"` row) is refused with 404 (never 403 — a 403 would
/// confirm the local account's existence to the IdP) and audited at
/// `scim.user.provenance_denied`.
///
/// Follows the CaRoutes pattern: a production overload wraps httplib::Server
/// in an HttplibRouteSink; a test-only overload registers directly against
/// an HttpRouteSink so tests can dispatch in-process (no socket, TSan-safe,
/// #438).

#include <yuzu/server/auth.hpp>
#include <yuzu/server/scim_store.hpp>

#include "http_route_sink.hpp"

#include <httplib.h>

#include <string>

namespace yuzu::server {

class AuditStore;
struct Config;

/// Testable core of the `--scim-enable` fail-closed boot guard (SOC 2 CC6.2,
/// S-BOOTGUARD-TEST) — extracted from main.cpp so the token/HTTPS
/// preconditions have direct unit coverage instead of only being exercised
/// end-to-end by booting a server. Mirrors `break_glass_account_problem`'s
/// pattern (auth_db.hpp): a thin main-side wrapper logs `err` and returns
/// EXIT_FAILURE. Returns true (leaving `err` untouched) when the
/// configuration is safe to boot with: SCIM disabled, or SCIM enabled with
/// BOTH a non-empty token AND HTTPS. Never touches disk/network — pure
/// config validation.
bool scim_boot_guard_ok(const Config& cfg, std::string& err);

class ScimRoutes {
public:
    /// Production overload — wraps `svr` in an HttplibRouteSink and delegates.
    /// `scim_store`/`auth_mgr`/`audit_store` are non-owning; the caller (server.cpp)
    /// only constructs/registers this class when `--scim-enable` is set, so in
    /// practice all three are always non-null on this path — the null checks in
    /// scim_routes.cpp are defense-in-depth for the test harness and any future
    /// caller that constructs it before its deps are ready.
    void register_routes(httplib::Server& svr, ScimStore* scim_store, auth::AuthManager* auth_mgr,
                         AuditStore* audit_store);

    /// Testable overload — register against an in-process sink (no socket).
    void register_routes(HttpRouteSink& sink, ScimStore* scim_store, auth::AuthManager* auth_mgr,
                         AuditStore* audit_store);
};

} // namespace yuzu::server
