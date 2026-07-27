#pragma once

/// @file kek_routes.hpp
/// KEK (key-encryption-key) rotation REST surface (#2395): `/api/v1/secrets/kek/*`.
///
/// - `POST /api/v1/secrets/kek/rotate` — `Security:Write`. Mint a new KEK
///   version and re-wrap every registered secret row under it.
/// - `POST /api/v1/secrets/kek/rewrap` — `Security:Write`. Idempotent RESUME
///   of a rotation that advanced the active version but did not finish
///   re-wrapping every row (see `KekOpResult::Failure::HalfCommitted` below).
/// - `GET  /api/v1/secrets/kek/status` — `Security:Read`. Current active
///   version + oldest version still referenced by a live secret row + whether
///   rotation is complete (every row is on the active version).
///
/// NO RETIRE ROUTE — deliberate. `SecretCodec::retire_kek` exists and is
/// tested, but it is NOT exposed here and must not be, and `KekOpResult`
/// carries no `retirable` field advertising which versions could be retired.
///
/// Retiring a KEK deletes key material, and #2525 documents a write race that
/// makes that unsafe: `SecretCodec::encrypt()` snapshots the active version,
/// releases its mutex, and the CALLER persists the blob afterwards — so a
/// retirement can pass its "no rows reference this version" check and delete
/// the key while an in-flight write is still about to commit a blob wrapped
/// under it. That blob is then permanently undecryptable. This happens on a
/// single server; it is not an HA-only hazard, and no lock this module could
/// take would close it, because ordinary secret writers do not participate.
///
/// Advertising a version as retirable while providing no safe way to retire it
/// would be worse than silence. Do not add a retire route, a `retirable` list,
/// or any "safe to delete" hint without closing #2525 first.
///
/// The crypto + Postgres access (`pg::SecretCodec`, `pg::PgPool`) is injected
/// as the `KekOps` seam so this module links neither — it only maps an
/// already-sanitised `KekOpResult` to HTTP. The seam implementation (server.cpp)
/// is responsible for classifying failures into `KekOpResult::Failure`; in
/// particular it MUST NOT let a codec-internal error string (which can carry
/// `PQerrorMessage` text) reach this struct — see rule B below.

#include <yuzu/server/auth.hpp>

#include "http_route_sink.hpp"

#include <httplib.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

/// Outcome of one KEK lifecycle operation, ALREADY SANITISED for external
/// consumption. The seam implementation classifies failures; the route only
/// maps them to HTTP. Codec-internal error strings (which carry
/// PQerrorMessage text) MUST NEVER reach this struct — see #2395 rule B.
struct KekOpResult {
    enum class Failure {
        None,
        Unavailable,     ///< codec or pool not available -> 503
        Conflict,        ///< another KEK operation is in flight -> 409
        Cooldown,        ///< too soon after the last rotate attempt -> 429
        HalfCommitted,   ///< rotate advanced the version then failed -> 500 + the resume instruction
        Internal,        ///< anything else -> 500, generic message only
    };
    Failure failure{Failure::None};
    std::uint32_t new_version{0};                 ///< rotate
    std::size_t   rows_rewrapped{0};              ///< rewrap only (rotate deliberately never sets this)
    std::uint32_t active_version{0};              ///< status
    std::optional<std::uint32_t> oldest_in_use{}; ///< status; nullopt = no secret rows exist
    bool rotation_complete{false};                ///< status
};

/// The three operations. Any may be empty (unset) -> route answers 503.
struct KekOps {
    std::function<KekOpResult()> rotate;
    std::function<KekOpResult()> rewrap;
    std::function<KekOpResult()> status;
};

class KekRoutes {
public:
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    // Returns false if the audit row could not be persisted (caller surfaces the
    // evidence-chain gap via `Sec-Audit-Failed`). Matches the canonical
    // bool-returning audit contract used across the other route modules
    // (ca_routes.hpp) so a privileged KEK rotate/rewrap can observe an
    // audit-persistence failure (#1240).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// Production overload — wraps `svr` in an HttplibRouteSink and delegates.
    void register_routes(httplib::Server& svr, PermFn perm_fn, AuditFn audit_fn, KekOps ops);

    /// Testable overload — register against an in-process sink (no socket).
    void register_routes(HttpRouteSink& sink, PermFn perm_fn, AuditFn audit_fn, KekOps ops);
};

} // namespace yuzu::server
