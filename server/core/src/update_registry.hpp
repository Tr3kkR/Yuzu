#pragma once

/// @file update_registry.hpp
/// OTA agent-update catalog (ADR-0061, Wave 4 ladder blind spot). Persists
/// per-(platform,arch,version) package metadata — sha256, filename, rollout
/// percentage, mandatory flag — that the gRPC OTA path (`CheckForUpdate`/
/// `DownloadUpdate` in `agent_service_impl.cpp`) and the Settings "Updates"
/// admin surface (`settings_routes.cpp`) both read. Package BINARIES stay a
/// node-local filesystem path under `update_dir_` — only the metadata moves
/// to shared Postgres; see the "Binaries stay node-local" note below.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement (`update_registry.update_packages`)
/// — pooled connections carry no per-store search_path. Mutate-and-return
/// uses `RETURNING` (the #1033-banning idiom), never `sqlite3_changes()`.
///
/// Posture (ADR-0012 §1): CONSTRUCTION is fail-closed — `is_open()` is false
/// (and the server sets `startup_failed_`) if the lease was empty or the
/// migration failed, whenever OTA is enabled (`cfg_.ota_enabled` defaults
/// `true` — opt-out via `--no-ota`, not an opt-in flag). This is a posture
/// upgrade from the SQLite era, which had no `is_open()` check at the
/// `server.cpp` call site at all. RUNTIME reads/writes deliberately keep
/// their pre-migration fail-SOFT shape (bare `bool`/`optional`/`vector`, no
/// `std::expected` widening): a degraded `latest_for`/`list_packages` reads
/// as "no update available this cycle" / "no packages configured", which is
/// the ADR-0036 deny-or-benign carve-out — an agent that misses an update
/// this heartbeat retries on the next one, and an admin who sees an empty
/// Updates list re-checks rather than having anything silently granted,
/// targeted, or enforced on their behalf. See the per-store ADR for the
/// explicit statement this playbook rule requires when a store declines the
/// typed-read widening. A degrade is still counted (never silent to
/// observability, only to the caller) via `set_metrics`' read/write
/// degrade-total families below.
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment —
/// no production fleet has ever run a pre-Postgres build of any Yuzu store).
/// The legacy `update_packages.db` is never read for data; construction
/// detects-and-warns via `legacy_sqlite_probe::warn_if_legacy_rows` if it
/// still holds rows, and logs a one-time "fresh start, no legacy backfill"
/// line. No secrets in this store (sha256 is a public content hash, not
/// secret material) — no `SecretCodec` work, no 0600 hardening obligation.
///
/// Binaries stay node-local: `update_dir_` (where uploaded package binaries
/// land, `binary_path()`) is unchanged — a plain filesystem path, same as
/// pre-migration. On today's single-server design
/// (`docs/adr/2002-high-availability-architecture.md`) this is a non-issue;
/// it becomes ADR-2002's concern once/if the server runs multi-replica
/// (fenced-leader/outbox model already scoped there) — not something this
/// migration solves.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

struct UpdatePackage {
    std::string platform; // "windows", "linux", "darwin"
    std::string arch;     // "x86_64", "aarch64"
    std::string version;  // "0.2.0+87"
    std::string sha256;   // hex-encoded SHA-256
    std::string filename; // "yuzu-agent-0.2.0-x64-windows.exe"
    bool mandatory{false};
    int rollout_pct{100};    // 0-100
    std::string uploaded_at; // ISO 8601 (kept TEXT — byte-identical round-trip, no caller changes)
    int64_t file_size{0};
};

class UpdateRegistry {
public:
    /// Borrows the shared pool and runs the `update_registry` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed. `update_dir` is unchanged from the
    /// pre-migration constructor — the node-local filesystem path package
    /// binaries live under (see the file header's "Binaries stay
    /// node-local" note).
    explicit UpdateRegistry(pg::PgPool& pool, const std::filesystem::path& update_dir);
    ~UpdateRegistry();

    UpdateRegistry(const UpdateRegistry&) = delete;
    UpdateRegistry& operator=(const UpdateRegistry&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics sink for the read/write degrade-total counters below.
    /// Set-before-traffic contract, same as every other migrated store's
    /// `set_metrics` (e.g. `InstructionStore`, `RuntimeConfigStore`). Optional
    /// — every method degrades silently-to-the-caller (per this class's
    /// documented deny-or-benign posture) whether or not a sink is wired;
    /// wiring one only adds the `yuzu_server_update_registry_{read,write}_
    /// degrade_total{reason}` observability signal (gov sre finding,
    /// adversarial review 2026-08-28).
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    void upsert_package(const UpdatePackage& pkg);
    void remove_package(const std::string& platform, const std::string& arch,
                        const std::string& version);
    std::vector<UpdatePackage> list_packages() const;
    std::optional<UpdatePackage> latest_for(const std::string& platform,
                                            const std::string& arch) const;

    /// Deterministic rollout: hash(agent_id) % 100 < rollout_pct. Pure — no DB.
    static bool is_eligible(const std::string& agent_id, int rollout_pct);

    /// Pure — no DB.
    std::filesystem::path binary_path(const UpdatePackage& pkg) const;

    /// Path to the package's detached CMS signature, if the operator supplied
    /// one at upload (#416/#3807). A SIDECAR beside the binary rather than a
    /// column on the row, mirroring how plugin signatures are stored, so the
    /// signature travels with the artifact and needs no schema migration.
    ///
    /// The server does not verify this and is deliberately not trusted to: the
    /// agent checks it against a trust anchor placed on disk at install time,
    /// out of band of this server entirely. Absent file means unsigned.
    std::filesystem::path signature_path(const UpdatePackage& pkg) const;

private:
    pg::PgPool& pool_;
    bool open_{false};
    std::filesystem::path update_dir_;
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
