#pragma once

/// @file software_inventory_store.hpp
/// Born-on-Postgres typed inventory projection (ADR-0016, schema
/// `software_inventory_store`). The read-optimized home for the daily-sync
/// framework's `installed_software` source — normalized rows so fleet-wide
/// queries ("which devices run X < v") are first-class and the schema ports off
/// Postgres easily.
///
/// COEXISTS with the generic per-source `InventoryStore` (the sync framework's
/// baseline blob store, which also backs the scope-walking `kInventoryQuery`
/// source + the eval engine). This class is NOT a replacement — it is the typed
/// projection for the one source that needs structured fleet queries today.
/// Future high-query sources get their own typed table in this same store.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement,
/// uses `RETURNING`. Normalized rows only — NO JSONB/GIN. Failure posture splits by
/// axis (ADR-0012 §1 + ADR-0016 §7) — unlike `OfflineEndpointStore` there is NO
/// in-memory authoritative read layer; this store IS the only server-side read
/// representation of installed software, so it is NOT durability-on-top for reads:
///   - **Data:** a projection — the agent + weekly full-floor are the source of truth.
///   - **Ingest:** fail-soft — a transient PG outage returns kError + nacks; the next
///     sync + the floor self-heal (the agent re-pushes). A blip degrades durability,
///     never correctness.
///   - **Reads:** AUTHORITATIVE — a store/pool/query failure returns `std::nullopt`
///     (logged at warn), NEVER a silent empty. A silent-empty read on a fleet vuln
///     query ("which devices run <CVE>") reads as "installed nowhere" — the fail-open
///     A4 violation ADR-0016 §7 forbids ("surface errors, never silent-empty").
///     `nullopt` = degraded (could not read); an empty *value* = a genuine zero-row
///     result. Staleness is acceptable (return the last projection); failure-as-empty
///     is not.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// One installed-software entry. **Machine-wide scope only** — no per-user /
/// username / SID / user-path (ADR-0016: no PII, no works-council trigger).
struct SoftwareEntry {
    std::string name;
    std::string version;
    std::string publisher;
    std::string install_date;
};

/// Outcome of a hash-skip ingest for one source (ADR-0016 §4).
enum class InventoryIngestOutcome {
    kStored,   ///< full payload accepted; the agent's rows were replaced
    kTouched,  ///< claimed hash matched the stored hash; last_seen bumped only
    kNeedFull, ///< cold cache / mismatch with no rows — server asks for a resend
    kError,    ///< pool/SQL failure (transient; the agent retries next cycle)
};

/// One fleet-query row: which agent carries which entry.
struct SoftwareFleetRow {
    std::string agent_id;
    SoftwareEntry entry;
};

/// Fleet-wide software query. Empty filters match all; results are capped.
struct SoftwareFleetQuery {
    std::string agent_id; ///< exact agent filter ("" = all agents)
    std::string name;     ///< exact software-name filter ("" = all names)
    int limit{1000};
    // No offset: see query_software (gov consistency N1) — keyset is the #1634 follow-up.
};

class SoftwareInventoryStore {
public:
    /// Borrows the shared pool and runs the `software_inventory_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was empty
    /// or the migration failed (the server fails closed before reaching here).
    explicit SoftwareInventoryStore(pg::PgPool& pool);

    SoftwareInventoryStore(const SoftwareInventoryStore&) = delete;
    SoftwareInventoryStore& operator=(const SoftwareInventoryStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Canonical content hash over a machine-scope software list — the SAME
    /// algorithm the agent uses (sorted+deduplicated; fields unit-separated
    /// 0x1F, entries record-separated 0x1E; SHA-256 hex), so the agent's
    /// claimed hash and the server's recomputed/stored hash are comparable
    /// (ADR-0016 §4). Pure/deterministic; takes its argument by value.
    [[nodiscard]] static std::string canonical_hash(std::vector<SoftwareEntry> entries);

    /// Hash-skip ingest for the `installed_software` source (ADR-0016 §4).
    ///  - `rows == std::nullopt` → hash-only report: compare `claimed_hash`
    ///    against the stored hash. Match → bump last_seen (kTouched); no record
    ///    or mismatch → kNeedFull.
    ///  - `rows` set → full payload: the server **recomputes** the canonical
    ///    hash from these rows and stores THAT (never trusts `claimed_hash`),
    ///    replacing all of this agent's rows + upserting the parent in one
    ///    transaction → kStored.
    /// `collected_at` is epoch seconds (0 → server wall-clock now).
    InventoryIngestOutcome apply_installed_software(
        std::string_view agent_id, std::string_view claimed_hash,
        const std::optional<std::vector<SoftwareEntry>>& rows, std::int64_t collected_at);

    /// All installed software for one agent (per-device drill-down), name-sorted.
    /// AUTHORITATIVE read: `std::nullopt` on a store/pool/query failure (degraded —
    /// distinct from an empty value = genuinely no rows). An empty `agent_id` is a
    /// precondition miss, not a degrade → empty value. Callers MUST surface a `nullopt`
    /// degrade (e.g. an error/banner), NOT `.value_or({})` it back into a silent empty —
    /// that re-opens the fail-open A4 violation this contract closes (gov UP-5).
    [[nodiscard]] std::optional<std::vector<SoftwareEntry>>
    get_agent_software(std::string_view agent_id);

    /// Fleet-wide query ("which agents run X"). Capped at a hard ceiling regardless
    /// of `limit`. AUTHORITATIVE read: `std::nullopt` on a store/pool/query failure
    /// (degraded — NEVER a silent empty; ADR-0016 §7). An empty value = no matches.
    [[nodiscard]] std::optional<std::vector<SoftwareFleetRow>>
    query_software(const SoftwareFleetQuery& q);

    /// Drop an agent's software inventory (e.g. on agent removal). Best-effort.
    void delete_agent(std::string_view agent_id);

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
