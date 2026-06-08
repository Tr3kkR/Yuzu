#pragma once

/// @file ca_routes.hpp
/// Internal-CA REST surface (PKI PR4): `/api/v1/ca/*`.
///
/// - `GET  /api/v1/ca/root`   — PUBLIC. The CA root certificate (PEM). Clients
///   and browsers need it to trust the install; it is public by definition.
/// - `GET  /api/v1/ca/crl`    — PUBLIC. The current CRL (DER). Revocation
///   distribution must be reachable by every client.
/// - `GET  /api/v1/ca/issued` — `Security:Read`. Issued-cert inventory (JSON).
/// - `POST /api/v1/ca/revoke` — `Security:Delete`. Revoke a serial; republishes
///   the CRL.
///
/// `POST /api/v1/ca/issue` (general operator-chosen-CN signing) is deliberately
/// NOT in M1: an operator-issued client leaf whose CN collides with an agent_id
/// could impersonate that agent at the #1118 identity gate, so it needs a
/// dedicated non-agent namespace + EKU policy — a tracked follow-up.
///
/// The crypto (CRL build, CA-key access) is injected as a callback so this module
/// links no `x509_ca`/`key_provider`; it only reads `CaStore` + calls back.

#include <yuzu/server/auth.hpp>

#include "ca_store.hpp"
#include "http_route_sink.hpp"

#include <httplib.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class CaRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    // Returns false if the audit row could not be persisted (caller surfaces the
    // evidence-chain gap via `Sec-Audit-Failed`). Matches the canonical
    // bool-returning audit contract used across the other route modules so a
    // privileged revoke can observe an audit-persistence failure (#1240).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// Build (and record a new version of) the current CRL over all revoked
    /// serials, signed by the CA. Returns the DER, or nullopt on failure / no CA.
    /// Implemented by ServerImpl (which holds the CA key); keeps this module free
    /// of crypto deps.
    using PublishCrlFn = std::function<std::optional<std::vector<std::uint8_t>>()>;

    /// Production overload — wraps `svr` in an HttplibRouteSink and delegates.
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         CaStore* ca_store, PublishCrlFn publish_crl_fn);

    /// Testable overload — register against an in-process sink (no socket).
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         CaStore* ca_store, PublishCrlFn publish_crl_fn);
};

} // namespace yuzu::server
