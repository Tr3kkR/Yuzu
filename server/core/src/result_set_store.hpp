#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

// ─────────────────────────────────────────────────────────────────────────────
// Result sets — the unit of composable scope ("scope walking").
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
enum class ResultSetError { NotFound, NotOwner, QuotaExceeded, PinLimit, Pinned, DbError };

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
    static constexpr int kMaxPinsPerOwner = 50;          // pin-storm guard
    static constexpr int kLineageDepthCap = 10;          // breadcrumb truncation

    explicit ResultSetStore(const std::filesystem::path& db_path);
    ~ResultSetStore();

    ResultSetStore(const ResultSetStore&) = delete;
    ResultSetStore& operator=(const ResultSetStore&) = delete;

    bool is_open() const;

    // ── Create ───────────────────────────────────────────────────────────────
    /// Synchronous create: members are known now; lands `materialized`.
    std::expected<ResultSet, ResultSetError> create_materialized(
        const CreateRequest& req, const std::vector<std::string>& members);

    /// Asynchronous create: a command has been dispatched under `execution_id`;
    /// lands `pending`. The maintenance thread later calls materialize().
    std::expected<ResultSet, ResultSetError> create_pending(const CreateRequest& req,
                                                            const std::string& execution_id);

    // ── Read ─────────────────────────────────────────────────────────────────
    std::optional<ResultSet> get(const std::string& id) const;
    /// Owner-scoped list, sorted last_used_at then created_at DESC. `cursor` is
    /// an opaque created_at|id token ("" for first page). Returns up to `limit`
    /// rows; `out_next_cursor` is set empty when the last page is reached.
    std::vector<ResultSet> list_by_owner(const std::string& owner, const std::string& cursor,
                                         int limit, std::string& out_next_cursor) const;
    std::vector<std::string> members(const std::string& id, const std::string& cursor, int limit,
                                     std::string& out_next_cursor) const;
    std::vector<LineageNode> lineage(const std::string& id) const;
    bool contains(const std::string& id, const std::string& device_id) const;
    /// Resolve an owner-scoped alias to a canonical id. Empty if not found.
    std::optional<std::string> resolve_alias(const std::string& owner,
                                             const std::string& name) const;
    int count_for_owner(const std::string& owner) const;
    int count_pinned_for_owner(const std::string& owner) const;

    /// Fleet-wide aggregate counts for observability gauges.
    struct Counts {
        int total{0};
        int pinned{0};
        int pending{0};
    };
    Counts counts() const;

    // ── Mutate ───────────────────────────────────────────────────────────────
    std::expected<ResultSet, ResultSetError> pin(const std::string& id);
    std::expected<ResultSet, ResultSetError> unpin(const std::string& id);
    /// Extend ttl_at to max(ttl_at, now + kDefaultTtlSeconds) and bump
    /// last_used_at. Called when a set is used as the scope of a new operation.
    void touch(const std::string& id);
    std::expected<void, ResultSetError> delete_set(const std::string& id);

    // ── Async materialisation (server maintenance thread) ────────────────────
    std::vector<PendingSet> list_pending() const;
    /// Populate members, flip status → materialized, set device_count.
    std::expected<void, ResultSetError> materialize(const std::string& id,
                                                    const std::vector<std::string>& members);
    void mark_failed(const std::string& id, const std::string& reason);

    // ── GC ───────────────────────────────────────────────────────────────────
    /// Delete unpinned rows past TTL; cascades to members. Returns count removed.
    int gc_sweep();

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;
    void create_tables();

    // Internal helpers, called under an already-held lock (no re-lock).
    static std::string generate_id();
    std::optional<ResultSet> get_impl(const std::string& id) const;
    int count_pinned_for_owner_unlocked(const std::string& owner) const;
    std::expected<ResultSet, ResultSetError> insert_row_impl(
        const CreateRequest& req, ResultSetStatus status, const std::string& execution_id,
        const std::vector<std::string>& members, int64_t member_count);
};

} // namespace yuzu::server
