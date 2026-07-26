#pragma once

/// @file result_set_store.hpp
/// Migrated Postgres store (ADR-0006, ADR-0036, schema `result_set_store`) for
/// the scope-walking result-set primitive (design: docs/scope-walking-design.md).
/// Was `result_sets.db` (SQLite); migrated per the ADR-0009 one-time backfill
/// mechanism — see `migrate_from_sqlite()`.
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard, both construction and
/// runtime. The database IS the source of truth for scope-walking lineage —
/// there is no in-memory fallback. Construction failure (`!is_open()`) is
/// fatal (server.cpp sets `startup_failed_`), same as every other
/// Postgres-backed store.
///
/// **Every authorization/targeting-relevant read is type-distinguishable
/// (2026-07-25, program policy — see `docs/postgres-store-playbook.md`
/// "Authoritative reads must be type-distinguishable").** `get`, `contains`,
/// `resolve_alias`, and `member_set_owned` return `std::expected<T,
/// ResultSetError>` — a runtime DB error is `std::unexpected(DbError)`,
/// NEVER an empty/false/nullopt value indistinguishable from a genuine
/// "not found" or "not a member". This is load-bearing: `member_set_owned`
/// backs `AgentRegistry::evaluate_scope`'s `from_result_set:` membership
/// check, and under a `NOT from_result_set:<id>` scope a silently-empty
/// membership (the pre-2026-07-25 behavior) INVERTS to "matches every
/// device" — a concrete command-dispatch fleet-wide fail-open, not a
/// theoretical one. Every caller of these four methods MUST apply the
/// reviewer test: "if this value were silently empty/false, could any
/// downstream branch grant/target/enforce/skip/invert(NOT)/report success?
/// If yes, fail closed (abort/503) on `DbError` — never treat it as
/// empty-container." `list_by_owner`, `members`, `lineage`,
/// `count_for_owner`, `counts`, and `list_pending` remain plain-optional/
/// container reads (deny-or-benign failure modes; not yet widened — tracked
/// as a follow-up, see ADR-0036).
///
/// Substrate contract (ADR-0008): the store holds a `PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement (`result_set_store.result_sets`)
/// — pooled connections carry no per-store search_path. Mutate-and-return uses
/// `RETURNING` (the #1033-banning idiom), never `sqlite3_changes()`. No
/// secrets — plain columns, no `SecretCodec`.
//
// A result set is a named, TTL-bounded, lineage-tracked set of device IDs
// produced by a query, action result, or operator-curated list. Each narrowing
// step in an investigation produces a new result set whose `parent_id` points
// at the set it refined, so a SELECT walking `parent_id` reconstructs the
// operator's full reasoning chain (design: docs/scope-walking-design.md).
//
// Producers come in two flavours:
//   • synchronous  (inventory query, manual curation) — members known at create
//     time → row lands in status `materialized`.
//   • asynchronous (TAR SQL, instruction-result) — a command is dispatched and
//     responses trickle in over seconds–minutes; the row lands `pending` with a
//     `source_execution_id`, and the server's maintenance thread materialises it
//     once the execution reaches a terminal state.
// ─────────────────────────────────────────────────────────────────────────────

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Lifecycle state of a result set's membership list.
enum class ResultSetStatus { Pending, Materialized, Failed };

const char* to_string(ResultSetStatus s);
ResultSetStatus result_set_status_from(std::string_view s);

/// Source that produced a result set. Mirrors design §3.2 `source_kind`.
/// Carried as a plain string in the row so future kinds need no schema change.
namespace source_kind {
inline constexpr std::string_view kInventoryQuery = "inventory_query";
inline constexpr std::string_view kTarQuery = "tar_query";
inline constexpr std::string_view kInstructionResult = "instruction_result";
inline constexpr std::string_view kManualCurate = "manual_curate";
} // namespace source_kind

/// Row metadata for a result set (members live in a separate table).
struct ResultSet {
    std::string id;              // "rs_<time-hex><rand-hex>", lexically sortable
    std::string name;            // operator alias, unique per owner; may be empty
    std::string owner_principal; // result sets are per-operator
    int64_t created_at{0};       // epoch seconds
    int64_t ttl_at{0};           // epoch seconds; GC'd when now > ttl_at AND !pinned
    int64_t last_used_at{0};     // epoch seconds; bumped by touch()
    bool pinned{false};
    std::optional<std::string> parent_id; // lineage edge; empty for ground sets
    std::string source_kind;              // see source_kind:: constants
    std::string source_payload;           // JSON; enough to re-evaluate (design §3.2)
    ResultSetStatus status{ResultSetStatus::Materialized};
    std::string source_execution_id;      // set for async producers; else empty
    std::string matcher;                  // JSON matcher for instruction-result; else empty
    int64_t device_count{0};
};

/// One step in a lineage chain (design §6 `/lineage`).
struct LineageNode {
    std::string id;
    std::string name;
    std::string source_kind;
    int64_t device_count{0};
};

/// A pending set awaiting async materialisation, surfaced to the server's
/// maintenance thread. The thread owns the response→matcher→members logic.
struct PendingSet {
    std::string id;
    std::string owner_principal;
    std::string source_kind;
    std::string source_execution_id;
    std::string matcher;
    int64_t created_at{0};
};

/// Typed failure surface; the REST layer maps these to the error taxonomy
/// (RESULT_SET_NOT_FOUND, RESULT_SET_NOT_OWNER, RESULT_SET_QUOTA, PIN_LIMIT,
/// RESULT_SET_EXPIRED) and the corresponding HTTP status.
enum class ResultSetError { NotFound, NotOwner, QuotaExceeded, PinLimit, Pinned, TooManyMembers, DbError };

const char* to_string(ResultSetError e);

/// Parameters for creating a result set. `members` (for sync create) and
/// `execution_id` (for async create) are supplied to the respective methods.
struct CreateRequest {
    std::string name;            // optional alias
    std::string owner_principal; // required
    std::optional<std::string> parent_id;
    std::string source_kind;
    std::string source_payload; // JSON
    std::string matcher;        // JSON; only meaningful for async instruction-result
};

class ResultSetStore {
public:
    // Lifecycle / sizing knobs (design §3.3, §3.4).
    static constexpr int64_t kDefaultTtlSeconds = 3600;  // 1 hour
    static constexpr int kMaxPerOwner = 10000;           // hard create cap
    static constexpr int kMaxMembersPerSet = 100000;     // per-set member cap (DoS guard)
    static constexpr int kMaxPinsPerOwner = 50;          // pin-storm guard
    static constexpr int kLineageDepthCap = 10;          // breadcrumb truncation

    /// Borrows the shared pool and runs the `result_set_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed.
    explicit ResultSetStore(pg::PgPool& pool);

    ResultSetStore(const ResultSetStore&) = delete;
    ResultSetStore& operator=(const ResultSetStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// One-time, idempotent legacy-SQLite backfill (ADR-0009). Call once at
    /// server startup, BEFORE the server serves, after construction has
    /// proven the Postgres schema is open. Idempotency is tracked by a
    /// dedicated marker row (never inferred from `result_sets` being empty —
    /// GC legitimately empties it over the store's lifetime). Fails CLOSED on
    /// any error — the caller must treat `false` as a fatal startup error,
    /// same as `!is_open()` (authoritative store: never serve on top of a
    /// partially-migrated schema). Returns true (no-op) when
    /// `legacy_db_path` does not exist (fresh install) after stamping the
    /// marker. Opens the legacy file READ-ONLY and never deletes it — the
    /// one-release rollback-window file is retained by the caller.
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

    // ── Create ───────────────────────────────────────────────────────────────
    /// Synchronous create: members are known now; lands `materialized`.
    std::expected<ResultSet, ResultSetError> create_materialized(
        const CreateRequest& req, const std::vector<std::string>& members);

    /// Asynchronous create: a command has been dispatched under `execution_id`;
    /// lands `pending`. The maintenance thread later calls materialize().
    std::expected<ResultSet, ResultSetError> create_pending(const CreateRequest& req,
                                                            const std::string& execution_id);

    // ── Read ─────────────────────────────────────────────────────────────────
    /// `std::unexpected(DbError)` on a runtime Postgres error — type-
    /// distinguishable from a genuine absent row (`std::optional` holding
    /// `nullopt`). Backs the owner gate at `scope_yaml.cpp` / the dashboard
    /// and REST result-set routes; a caller MUST treat `DbError` as "cannot
    /// verify ownership" (fail closed / 503), never as "not found" (404) —
    /// collapsing the two would let a transient DB blip read as a clean
    /// not-found on an authorization-relevant lookup.
    std::expected<std::optional<ResultSet>, ResultSetError> get(const std::string& id);
    /// Owner-scoped list, sorted last_used_at then created_at DESC. `cursor` is
    /// an opaque created_at|id token ("" for first page). Returns up to `limit`
    /// rows; `out_next_cursor` is set empty when the last page is reached.
    /// NOT YET widened to a typed error (deny-or-benign failure mode — an
    /// empty page just re-renders the sidebar empty, no grant/target/enforce
    /// downstream); tracked as a follow-up alongside `members`/`lineage`.
    std::vector<ResultSet> list_by_owner(const std::string& owner, const std::string& cursor,
                                         int limit, std::string& out_next_cursor);
    std::vector<std::string> members(const std::string& id, const std::string& cursor, int limit,
                                     std::string& out_next_cursor);
    /// Lineage chain root→leaf, walking parent_id. Owner-filtered: the walk
    /// stops at the first ancestor not owned by `owner`, so a child parented
    /// onto another operator's set cannot leak that set's metadata (review B2).
    std::vector<LineageNode> lineage(const std::string& id, const std::string& owner);
    /// `std::unexpected(DbError)` on a runtime error — see the type-
    /// distinguishable-reads note above the `get()` declaration. (No current
    /// production caller — `AgentRegistry`'s membership check uses
    /// `member_set_owned` instead; widened for API consistency and the
    /// authorization-primitive contract this store advertises.)
    ///
    /// CAUTION: `!contains(...)` tests the ERROR state (`std::expected`'s
    /// `operator!`/`operator bool`), NOT "device is not a member" — a bare
    /// `!contains(...)` silently treats a DB error the same as "not a
    /// member" and a successful `false` the same as "degraded", both wrong.
    /// Check `.has_value()` first, then dereference (`**result` or
    /// `result.value()`) for the actual boolean membership answer.
    std::expected<bool, ResultSetError> contains(const std::string& id,
                                                 const std::string& device_id);
    /// All members of `id` iff owned by `owner`; empty set otherwise (absent id
    /// and "not owned" are intentionally indistinguishable — design's
    /// documented "stale/not-yours members drop silently" contract, review
    /// findings B1 + F). `std::unexpected(DbError)` on a runtime error is
    /// DISTINCT from both — see the type-distinguishable-reads note above.
    /// THE authorization gate for `AgentRegistry::evaluate_scope`'s
    /// `from_result_set:` scope kind: a caller that lets `DbError` fall
    /// through as an empty set converts a transient DB blip into "no
    /// members", which under a `NOT from_result_set:<id>` scope inverts to
    /// "every device matches" — the fleet-wide fail-open this contract exists
    /// to prevent. Callers MUST abort (not dispatch) on `DbError`.
    std::expected<std::unordered_set<std::string>, ResultSetError>
    member_set_owned(const std::string& id, const std::string& owner);
    /// Resolve an owner-scoped alias to a canonical id; `nullopt` if not
    /// found. `std::unexpected(DbError)` on a runtime error — see the
    /// type-distinguishable-reads note above the `get()` declaration. Feeds
    /// `resolve_scope_aliases()` (scope_yaml.cpp), which must PROPAGATE a
    /// `DbError` (abort resolution) rather than leaving the alias atom
    /// unresolved — an unresolved atom no-matches downstream and, under NOT,
    /// inverts to match-all, same class of fail-open as `member_set_owned`.
    std::expected<std::optional<std::string>, ResultSetError>
    resolve_alias(const std::string& owner, const std::string& name);
    int count_for_owner(const std::string& owner);
    int count_pinned_for_owner(const std::string& owner);

    /// Fleet-wide aggregate counts for observability gauges.
    struct Counts {
        int total{0};
        int pinned{0};
        int pending{0};
    };
    Counts counts();

    // ── Mutate ───────────────────────────────────────────────────────────────
    std::expected<ResultSet, ResultSetError> pin(const std::string& id);
    std::expected<ResultSet, ResultSetError> unpin(const std::string& id);
    /// Extend ttl_at to max(ttl_at, now + kDefaultTtlSeconds) and bump
    /// last_used_at. Called when a set is used as the scope of a new operation.
    void touch(const std::string& id);
    std::expected<void, ResultSetError> delete_set(const std::string& id);

    // ── Async materialisation (server maintenance thread) ────────────────────
    std::vector<PendingSet> list_pending();
    /// Populate members, flip status → materialized, set device_count.
    std::expected<void, ResultSetError> materialize(const std::string& id,
                                                    const std::vector<std::string>& members);
    void mark_failed(const std::string& id, const std::string& reason);

    // ── GC ───────────────────────────────────────────────────────────────────
    /// Delete unpinned rows past TTL; cascades to members. Returns count removed.
    int gc_sweep();

private:
    pg::PgPool& pool_;
    bool open_{false};

    static std::string generate_id();
    // Shared body for create_materialized/create_pending: dedups members,
    // enforces the per-set cap client-side, then inserts the row + member
    // batch inside ONE transaction (quota check + insert + members atomic).
    std::expected<ResultSet, ResultSetError> insert_row_impl(
        const CreateRequest& req, ResultSetStatus status, const std::string& execution_id,
        const std::vector<std::string>& members);
};

} // namespace yuzu::server
