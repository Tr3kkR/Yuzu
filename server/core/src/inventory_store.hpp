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
/// (`inventory_store.inventory_data`), and uses `RETURNING` for
/// mutate-and-return — never `sqlite3_changes()` (#1033). No secrets
/// (ADR-0010 does not apply — `data_json` is plugin-collected inventory,
/// not credential material).
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
///  - **`delete_agent`**: returns true iff the DELETE executed successfully;
///    false on a lease timeout or SQL failure, so the decommission cascade
///    records the store Failed rather than a false "erased" (unchanged
///    contract from the SQLite implementation).
///  - **`migrate_from_sqlite`**: the one-time first-boot backfill (ADR-0009).
///    FAILS CLOSED — see its own doc comment below.

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

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

    /// One-time, idempotent first-boot backfill from the legacy SQLite
    /// `inventory.db` (ADR-0009/0037). Call once at startup, before serving.
    ///
    /// Contract:
    ///  - If the backfill has already completed (stamped in this schema's
    ///    `backfill_state` table), returns true immediately — every boot
    ///    after the first is a cheap single-row lookup.
    ///  - If `legacy_db_path` does not exist, stamps "nothing to backfill"
    ///    and returns true (a fresh install never had a legacy file).
    ///  - Otherwise opens the legacy SQLite file READ-ONLY, copies every row
    ///    of its `inventory_data` table into
    ///    `inventory_store.inventory_data` via `INSERT ... ON CONFLICT
    ///    (agent_id, plugin) DO NOTHING` (never clobbers a row a live agent
    ///    has already re-reported since this boot sequence started), all
    ///    inside one transaction, then stamps completion. The legacy file is
    ///    never written to — it stays the rollback net for one release
    ///    (ADR-0009) — and is not deleted by this call.
    ///  - FAILS CLOSED: returns false on any legacy-open/read error or any
    ///    Postgres write error. The caller MUST treat `false` as a fatal
    ///    startup error (`startup_failed_ = true` in `server.cpp`) — per
    ///    ADR-0009, the server refuses to start rather than serve
    ///    half-migrated inventory data.
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

    /// Upsert inventory data for an agent+plugin pair. FAIL-SOFT ingest: a
    /// lease/query failure is logged and this returns without throwing — the
    /// agent's next report re-sends the same blob. If data already exists for
    /// (agent_id, plugin), it is replaced.
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
    /// empty value = no rows matched.
    [[nodiscard]] std::optional<std::vector<InventoryRecord>> query(const InventoryQuery& q) const;

    /// Get all inventory records for a specific agent. AUTHORITATIVE read:
    /// same nullopt-on-degrade contract as `query` (this delegates to it).
    [[nodiscard]] std::optional<std::vector<InventoryRecord>>
    get_agent_inventory(const std::string& agent_id) const;

    /// Delete inventory data for an agent (e.g., on agent removal). Returns true
    /// iff the DELETE executed successfully; false on a lease timeout or a
    /// query failure, so the decommission cascade can record the store as
    /// Failed rather than a false "erased".
    [[nodiscard]] bool delete_agent(const std::string& agent_id);

    /// Count total inventory records. AUTHORITATIVE read: `std::nullopt` on a
    /// store/pool/query degrade, NEVER a silent zero.
    [[nodiscard]] std::optional<int64_t> count() const;

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
