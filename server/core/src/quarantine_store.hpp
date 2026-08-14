#pragma once

/// @file quarantine_store.hpp
/// Migrated Postgres store (ADR-0006/0009, schema `quarantine_store`) for
/// Guardian device-quarantine bookkeeping — which agents are currently
/// network-isolated, who isolated them, why, and the full history. Single
/// table, no foreign keys, no secret-bearing columns.
///
/// Posture per ADR-0012 §1: **authoritative** — an active quarantine record
/// is live security containment state, not expendable telemetry (per
/// `docs/yuzu-guardian-design-v1.1.md` §11.7, "Quarantine is a terminal
/// state" that persists until an administrator explicitly lifts it). A
/// runtime error is surfaced via `std::expected`/`std::optional`, never
/// papered over with a silent empty/false result — a `get_status` or
/// `list_quarantined` that silently degraded to "not quarantined" / "nothing
/// quarantined" would mask an ACTIVE containment (fail-open).
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement
/// (`quarantine_store.quarantine_records`) — pooled connections carry no
/// per-store search_path. Mutate-and-return uses `RETURNING`, never
/// `sqlite3_changes()`.
///
/// "At most one active record per agent" is enforced by a partial unique
/// index (`quarantine_records(agent_id) WHERE status = 'active'`), not an
/// in-process mutex — `quarantine_device` is a single `ON CONFLICT ... DO
/// NOTHING` statement, race-safe under concurrent Postgres connections in a
/// way the legacy SQLite `shared_mutex` (scoped to one `sqlite3*` handle)
/// never had to be. `release_device` is a single guarded `UPDATE ... WHERE
/// status = 'active'` (the #3062 `cancel_job` pattern), not lock-then-check.
///
/// Backfill (ADR-0009) is MANDATORY, not skippable: an active quarantine
/// record is live security state whose loss silently un-quarantines a
/// device in the server's view. Fingerprint-verified (ADR-0040 pattern,
/// `RbacStore`/`DiscoveryStore` the reference implementations), but ported
/// with a design difference from `DiscoveryStore` — see
/// `docs/adr/0047-quarantine-store-postgres-migration.md` "no natural
/// per-row key" for why the row inserts and the completion marker commit
/// together in one advisory-locked transaction rather than relying on a
/// per-row `ON CONFLICT` idiom.
///
/// Out of scope: the agent-side quarantine firewall enforcement (§11.7) is
/// untouched — this store is only the server-side bookkeeping.

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Prefix on every `quarantine_device`/`release_device` `unexpected(msg)`
/// that reflects a genuine store/pool/query failure (as opposed to a
/// business/state error like "already quarantined") — the route classifier
/// (`rest_api_v1.cpp`) keys off this to answer 503 rather than 400, mirroring
/// `DeploymentStore::kDeploymentDbErrorPrefix` (adversarial-review MEDIUM
/// hardening round, 2026-08-12: write routes previously collapsed every
/// failure, including genuine outages, to 400). A future rename of this
/// prefix must not silently regress every classified 503 back to 400 —
/// callers key off the shared constant, never a local copy of the literal.
inline constexpr const char* kQuarantineDbErrorPrefix = "db_error: ";

struct QuarantineRecord {
    std::string agent_id;
    std::string status; // "active" or "released"
    std::string quarantined_by;
    std::int64_t quarantined_at{0};
    std::int64_t released_at{0};
    std::string whitelist; // comma-separated IPs
    std::string reason;
};

class QuarantineStore {
public:
    /// Borrows the shared pool and runs the `quarantine_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before
    /// reaching here in production).
    explicit QuarantineStore(pg::PgPool& pool);

    QuarantineStore(const QuarantineStore&) = delete;
    QuarantineStore& operator=(const QuarantineStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the backfill-result counter
    /// (`yuzu_server_quarantine_backfill_total{result}`) and the read-degrade
    /// counter (`yuzu_server_quarantine_read_degrade_total{reason}`). Set
    /// ONCE during single-threaded startup, before serving; a null registry
    /// (default, e.g. unit tests) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    // ── Quarantine operations ────────────────────────────────────────────

    /// Quarantine a device. `std::unexpected("device is already
    /// quarantined")` when an active record already exists for `agent_id`
    /// (the partial unique index conflict, a business/state error — 400 at
    /// REST); any other `unexpected(msg)` a genuine store/pool/query
    /// failure, prefixed `kQuarantineDbErrorPrefix` so the REST route
    /// classifies it 503. AUTHORITATIVE write.
    [[nodiscard]] std::expected<void, std::string>
    quarantine_device(const std::string& agent_id, const std::string& by,
                      const std::string& reason, const std::string& whitelist);

    /// Release a device from quarantine. `std::unexpected("device is not
    /// quarantined")` when no active record exists for `agent_id` (a
    /// business/state error — 400 at REST); any other `unexpected(msg)` a
    /// genuine store/pool/query failure, prefixed `kQuarantineDbErrorPrefix`
    /// so the REST route classifies it 503. AUTHORITATIVE write.
    [[nodiscard]] std::expected<void, std::string> release_device(const std::string& agent_id);

    /// The current active record for `agent_id`, if any. AUTHORITATIVE read:
    /// `std::unexpected(msg)` on a store/pool/query failure (prefixed
    /// `kQuarantineDbErrorPrefix`); a value holding `std::nullopt` when
    /// genuinely not quarantined (including an empty `agent_id`, a
    /// precondition miss); a value holding the row when found.
    [[nodiscard]] std::expected<std::optional<QuarantineRecord>, std::string>
    get_status(const std::string& agent_id);

    /// Every currently-active quarantine record, newest first.
    /// AUTHORITATIVE read: `std::nullopt` on a store/pool/query failure —
    /// NEVER a silent empty (an empty *value* is a genuinely empty result).
    [[nodiscard]] std::optional<std::vector<QuarantineRecord>> list_quarantined();

    /// Full quarantine history (active and released) for `agent_id`, newest
    /// first. AUTHORITATIVE read: `std::nullopt` on a store/pool/query
    /// failure; an empty vector for a genuinely empty `agent_id` or a
    /// genuinely history-less agent.
    [[nodiscard]] std::optional<std::vector<QuarantineRecord>>
    get_history(const std::string& agent_id);

    /// MANDATORY one-time, idempotent backfill (ADR-0009) of a legacy
    /// `quarantine.db` SQLite file into this Postgres schema,
    /// fingerprint-verified per the RbacStore/DiscoveryStore reference shape
    /// (ADR-0040/0044 pattern — see the header doc above and ADR-0047 for
    /// why this store's design differs from DiscoveryStore's). Runs at
    /// startup, before serving; the caller (server.cpp) fails closed on a
    /// `false` return, matching every other MANDATORY-backfill store.
    /// Returns true when already migrated (idempotent short-circuit), when a
    /// fresh install has no legacy file, or when the migration completed and
    /// reconciled successfully.
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
