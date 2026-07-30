#pragma once

/// @file inventory_store.hpp
/// Generic per-source inventory blob store (Issue 7.17) — born on SQLite,
/// migrated to Postgres (ADR-0006/0008/0009/0037, schema `inventory_store`).
/// The sync-framework's generic `(agent_id, plugin) -> data_json` home for
/// every source that has NOT been promoted to its own typed projection; it
/// backs the scope-walking `kInventoryQuery` source + the inventory eval
/// engine (`inventory_eval.hpp`).
///
/// COEXISTS with `SoftwareInventoryStore` (ADR-0016, schema
/// `software_inventory_store`) — this is NOT that store's migration. The
/// typed sources (`installed_software`, `app_perf`, `device_ci`,
/// `software_licensing`) are skipped by the generic gateway/direct ingest
/// loop (`is_typed_inventory_source`) precisely so their rows never land
/// here; every OTHER plugin's blob still lands in this store. See
/// `docs/postgres-migration-ladder.md` and ADR-0037.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement
/// (`inventory_store.inventory_data`). Mutators check the `PgResult` status
/// directly rather than `sqlite3_changes()` (#1033); none needs `RETURNING`
/// (no caller consumes an affected-row count). Generic plugins must not emit
/// credentials or secret material: `data_json` is stored as plaintext and its
/// sensitivity is otherwise plugin-dependent (ADR-0010).
///
/// Failure posture (ADR-0012 §1), split by operation class:
///  - **Ingest (`upsert`)**: FAIL-SOFT. A transient lease/query failure logs
///    a warning and returns — never throws, never blocks the gRPC/gateway
///    ingest thread. The agent's next report re-sends the same blob, so a
///    dropped write self-heals (mirrors `SoftwareInventoryStore`'s ingest
///    posture).
///  - **Reads (`list_tables`, `get`, `query`, `get_agent_inventory`,
///    `count`)**: AUTHORITATIVE. A store/pool/query failure is reported as a
///    degrade — `std::nullopt` for the list/count reads, `std::unexpected(
///    InventoryReadError::kDegraded)` for the single-record `get` — NEVER a
///    silent empty. An empty *value* is a genuine zero-row result; a degrade
///    means the store could not be read at all. Callers MUST surface a
///    degrade (503 / banner), never `.value_or({})` it into a silent empty —
///    that re-opens the fail-open hole ADR-0016 §7 / the playbook's
///    anti-patterns list forbid.
///  - **`delete_agent`**: erases both PostgreSQL and the retained rollback
///    SQLite copy, when present. It returns false unless both deletes commit,
///    so the decommission cascade never reports a false "erased" result.
///  - **`migrate_from_sqlite`**: the one-time first-boot backfill (ADR-0009).
///    FAILS CLOSED — see its own doc comment below.

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

// ── Data types ───────────────────────────────────────────────────────────────

struct InventoryRecord {
    std::string agent_id;
    std::string plugin;
    std::string data_json; // Structured JSON blob from the plugin
    int64_t collected_at{0};
};

struct InventoryTable {
    std::string plugin;
    int64_t agent_count{0};      // How many agents have reported this plugin
    int64_t last_collected{0};   // Most recent collection timestamp
};

struct InventoryQuery {
    std::string agent_id;   // Filter by agent (empty = all)
    std::string plugin;     // Filter by plugin (empty = all)
    int64_t since{0};       // epoch seconds, 0 = no lower bound
    int64_t until{0};       // epoch seconds, 0 = no upper bound
    int limit{100};
    int offset{0};
};

/// Error type for the authoritative single-record read. The success type is
/// `std::optional<InventoryRecord>`: a value == found, `std::nullopt` ==
/// genuinely no row for this (agent_id, plugin). `std::unexpected(kDegraded)`
/// == store/pool/query failure — the caller shows a degrade banner/503, never
/// a 404 (mirrors `DeviceInventoryStore::CiReadError` exactly; out-params are
/// forbidden in new code, docs/cpp-conventions.md, hence `std::expected`
/// rather than an enum + out-param).
enum class InventoryReadError { kDegraded };

// ── InventoryStore ──────────────────────────────────────────────────────────

class InventoryStore {
public:
    /// Borrows the shared pool and runs the `inventory_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before
    /// reaching here, so in production the migration runs against a
    /// proven-reachable database).
    explicit InventoryStore(pg::PgPool& pool);

    InventoryStore(const InventoryStore&) = delete;
    InventoryStore& operator=(const InventoryStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_inventory_read_degrade_total{reason, source="generic"}`, shared
    /// with the typed sibling stores) and the ingest-drop / query-truncation
    /// counters below. Set ONCE during single-threaded startup, before the
    /// gRPC/REST surfaces begin serving — the pointer is read without
    /// synchronisation on the serving threads, so a later swap would race. A
    /// null registry (the default, e.g. in unit tests) disables emission;
    /// every emit site is null-guarded.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// One-time, idempotent first-boot backfill from the legacy SQLite
    /// `inventory.db` (ADR-0009/0037). Call once at startup, before serving.
    ///
    /// Contract:
    ///  - If the backfill has already completed (stamped in this schema's
    ///    `backfill_state` table), returns true immediately — every boot
    ///    after the first is a cheap single-row lookup.
    ///  - If `legacy_db_path` does not exist, stamps "nothing to backfill"
    ///    and returns true (a fresh install never had a legacy file).
    ///  - Otherwise opens the legacy SQLite file READ-ONLY (via RAII owners —
    ///    no manual finalize/close), reads every row of its `inventory_data`
    ///    table, skips sources promoted to typed stores, and inserts each
    ///    remaining row into `inventory_store.inventory_data`
    ///    via `INSERT ... ON CONFLICT (agent_id, plugin) DO NOTHING` (never
    ///    clobbers a row a live agent has already re-reported since this boot
    ///    sequence started), each under its own SAVEPOINT inside one overall
    ///    transaction, then stamps completion. The backfill itself does not
    ///    modify the legacy file; during the one-release rollback window only
    ///    `delete_agent` may remove rows so an erasure cannot be resurrected
    ///    by rollback.
    ///  - A single BAD ROW (a legacy value that violates encoding/constraints —
    ///    e.g. invalid UTF-8) does NOT abort the backfill: its SAVEPOINT is
    ///    rolled back, the row is logged at warn + counted skipped, and the
    ///    loop continues. Skippable row-data failures are SQLSTATE classes
    ///    22, 23, and 54; every other/unknown class aborts unstamped. A row
    ///    with an empty/blank `agent_id` or `plugin` is
    ///    skipped the same way (never backfilled as an un-erasable orphan —
    ///    the decommission cascade's empty-id guard could never reach it).
    ///    This store is FAIL-SOFT / self-healing (the agent re-pushes), so one
    ///    malformed legacy blob must not permanently brick the server.
    ///  - FAILS CLOSED on a genuine INFRASTRUCTURE error — the initial
    ///    connection/lease, the backfill transaction's own BEGIN/SAVEPOINT/
    ///    COMMIT, a non-row-data/unknown INSERT SQLSTATE, or a `ROLLBACK TO
    ///    SAVEPOINT` that itself fails (the signal that the connection, not
    ///    just one row, is broken). The caller MUST treat `false` as fatal
    ///    error (`startup_failed_ = true` in `server.cpp`) — per ADR-0009, the
    ///    server refuses to start rather than serve against an unreachable
    ///    database.
    ///  - The `backfill_state.legacy_rows` stamp records the count of rows
    ///    actually inserted (per-statement affected-row count via
    ///    `PQcmdTuples`), not the size of the in-memory legacy row list —
    ///    skipped/orphaned/conflicting rows are not counted as inserted.
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

    /// Upsert inventory data for an agent+plugin pair. FAIL-SOFT ingest: a
    /// lease/query failure is logged and this returns without throwing — the
    /// agent's next report re-sends the same blob (a drop bumps
    /// `yuzu_inventory_ingest_dropped_total`). A blank (empty/whitespace-only)
    /// `agent_id` or `plugin` is REJECTED (logged, no write) — never persisted
    /// as an un-erasable orphan the decommission cascade's empty-id guard
    /// could never reach (GDPR). If data already exists for (agent_id,
    /// plugin), it is replaced ONLY when `collected_at` is not older than the
    /// stored row's — a reordered/duplicate older report can never clobber
    /// newer data (a same-instant re-report, `collected_at` equal, still
    /// updates).
    void upsert(const std::string& agent_id, const std::string& plugin,
                const std::string& data_json, int64_t collected_at = 0);

    /// List available inventory "tables" (distinct plugins with agent
    /// counts). AUTHORITATIVE read: `std::nullopt` on a store/pool/query
    /// degrade, NEVER a silent empty. An empty value = no plugins reported.
    [[nodiscard]] std::optional<std::vector<InventoryTable>> list_tables() const;

    /// Get inventory data for a specific agent+plugin. AUTHORITATIVE read:
    /// see `InventoryReadError` above for the three-state contract (degrade
    /// vs genuinely-absent vs found).
    [[nodiscard]] std::expected<std::optional<InventoryRecord>, InventoryReadError>
    get(const std::string& agent_id, const std::string& plugin) const;

    /// Query inventory across agents with filters. AUTHORITATIVE read:
    /// `std::nullopt` on a store/pool/query degrade, NEVER a silent empty. An
    /// empty value = no rows matched. When the result count hits the
    /// effective row limit or the aggregate 8 MiB payload budget, more rows
    /// may exist past what is returned — this is logged and bumps
    /// `yuzu_inventory_query_truncated_total` so an operator/caller can tell
    /// "capped at N" from "exactly N" (full keyset pagination is a follow-up).
    /// Governance M1 (2026-07-29): pass `truncated` to receive that signal in
    /// process — a caller that PERSISTS the result as a targeting set (the
    /// from-inventory-query result-set route) must refuse a capped read
    /// rather than materialise a silently-incomplete set; the metric alone
    /// cannot reach that decision point. Cap ceiling + exact-at-cap false
    /// positive tracked in #2633 (keyset pagination / limit+1 probe).
    [[nodiscard]] std::optional<std::vector<InventoryRecord>>
    query(const InventoryQuery& q, bool* truncated = nullptr) const;

    /// Get all inventory records for a specific agent. AUTHORITATIVE read:
    /// same nullopt-on-degrade and optional truncation contract as `query`
    /// (this delegates to it).
    [[nodiscard]] std::optional<std::vector<InventoryRecord>>
    get_agent_inventory(const std::string& agent_id, bool* truncated = nullptr) const;

    /// Delete inventory data for an agent from PostgreSQL and from the retained
    /// legacy SQLite rollback file, if it exists. Idempotent; returns false if
    /// either backing delete fails so the decommission cascade can retry and
    /// cannot report a false "erased".
    [[nodiscard]] bool delete_agent(const std::string& agent_id);

    /// Count total inventory records. AUTHORITATIVE read: `std::nullopt` on a
    /// store/pool/query degrade, NEVER a silent zero.
    [[nodiscard]] std::optional<int64_t> count() const;

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
    // Set by migrate_from_sqlite() during startup, before serving. Read later
    // by delete_agent(); there is no concurrent writer after startup.
    std::filesystem::path legacy_db_path_;
};

} // namespace yuzu::server
