#pragma once

/// @file notification_store.hpp
/// Postgres-backed operator notification feed (ADR-0006 Wave 2 migration,
/// schema `notification_store`). Persists the small toast/badge feed the
/// dashboard renders ("Agent Enrolled", "Execution Failed", …) — one flat
/// table, no foreign keys, no secret-bearing columns.
///
/// Substrate contract (ADR-0008): the store holds a `PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement
/// (`notification_store.notifications`) — pooled connections carry no
/// per-store search_path. Mutate-and-return uses `RETURNING` (the
/// #1033-banning idiom), never `sqlite3_changes()`.
///
/// Posture (ADR-0012 §1) is split, same shape as `ResultSetStore`'s
/// documented carve-out: construction and `migrate_from_sqlite` are
/// AUTHORITATIVE/fail-closed — a Postgres store that cannot open or backfill
/// is a fatal startup error (unread/dismissed state is operator-relevant,
/// not expendable telemetry, so backfill is MANDATORY per ADR-0009). Runtime
/// reads/writes below stay plain container/bool returns (never
/// `std::expected`) because NONE of them feed an authorization, targeting,
/// enforcement, or skip decision — `list_unread`/`list_all`/`count_unread`
/// back a dashboard badge and a display list, and `mark_read`/`dismiss`
/// affect only what is shown, never what runs. A transient DB error on any
/// of these degrades the display (empty list, stale badge); it never
/// silently grants, targets, or suppresses anything (the playbook's own
/// reviewer test in docs/postgres-store-playbook.md § "Authoritative reads
/// must be type-distinguishable").

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

struct Notification {
    int64_t id{0};
    int64_t timestamp{0}; // epoch MILLISECONDS (matches create()'s duration_cast<milliseconds>)
    std::string level;    // "info", "warn", "error", "success"
    std::string title;
    std::string message;
    bool read{false};
    bool dismissed{false};
};

class NotificationStore {
public:
    /// Borrows the shared pool and runs the `notification_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before
    /// reaching here, so in production the migration runs against a
    /// proven-reachable database).
    explicit NotificationStore(pg::PgPool& pool);

    NotificationStore(const NotificationStore&) = delete;
    NotificationStore& operator=(const NotificationStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wires the fleet-wide metrics sink. Optional (a null/never-called
    /// registry leaves `yuzu_server_notification_backfill_total` unemitted);
    /// call before `migrate_from_sqlite` so its very first outcome is
    /// counted, matching every sibling PG-backed store's construction-site
    /// wiring order.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// One-time, idempotent legacy-`notifications.db` backfill (ADR-0009).
    /// MANDATORY (unread/dismissed state is operator-relevant, not
    /// expendable telemetry) — fails closed on any error, including a
    /// missing/mismatched holder-side fingerprint verification (see the
    /// .cpp — docs/postgres-store-playbook.md "Local source absence never
    /// creates terminal migration state on its own", #2697). Legacy row ids
    /// are preserved (the dashboard's mark_read/dismiss reference them) and
    /// the identity sequence is advanced past the migrated max id in the
    /// SAME transaction as the row inserts, so a post-backfill create()
    /// cannot collide. Must run before the store serves any request. Emits
    /// `yuzu_server_notification_backfill_total{result="success"|"failed"}`
    /// via `set_metrics()`'s registry (matching the RbacStore/AuditStore
    /// `_backfill_total` family, at reduced label granularity — this store's
    /// single-transaction backfill has no multi-step fresh/completed split
    /// to report separately).
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

    /// Create a new notification. Returns the assigned id, or -1 on a
    /// closed store / query error (display-only: a failed persist means one
    /// fewer toast shown, never a suppressed enforcement action).
    int64_t create(const std::string& level, const std::string& title, const std::string& message);

    /// List all unread, non-dismissed notifications (newest first). Empty
    /// on a closed store or query error — the dashboard badge/list degrade
    /// to "nothing to show", which is the display-only failure mode this
    /// store's posture note above documents.
    std::vector<Notification> list_unread(int limit = 50);

    /// List all notifications (newest first).
    std::vector<Notification> list_all(int limit = 100, int offset = 0);

    /// Mark a notification as read. Returns true only if the write is
    /// confirmed to have affected exactly one row (`PQcmdTuples()`, never a
    /// bare `PGRES_COMMAND_OK` on the UPDATE — that status is identical
    /// whether the id matched or not). False on a closed store, a query
    /// error, or a nonexistent id — the caller must not treat this call as
    /// having succeeded, e.g. for an audit row asserting the mutation
    /// landed (adversarial-review, fjarvis: an audit entry is compliance
    /// evidence and must not assert success for a write that may never
    /// have reached Postgres).
    [[nodiscard]] bool mark_read(int64_t id);

    /// Dismiss a notification (soft-delete). Same confirmed-affected-row
    /// contract as `mark_read` — see its doc comment.
    [[nodiscard]] bool dismiss(int64_t id);

    /// Count unread, non-dismissed notifications. 0 on a closed store or
    /// query error (same display-only degrade as list_unread).
    std::size_t count_unread();

private:
    /// The actual backfill logic — `migrate_from_sqlite` is a thin wrapper
    /// that adds a single metric emission around this, so the metric can't
    /// drift out of sync with any of the function's many internal return
    /// points.
    [[nodiscard]] bool migrate_from_sqlite_impl(const std::filesystem::path& legacy_db_path);

    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
