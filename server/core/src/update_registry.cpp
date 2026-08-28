#include "update_registry.hpp"

#include "nvd_db.hpp" // compare_versions()
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <functional>
#include <string>
#include <utility>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "update_registry";

// Bounded acquires (ADR-0012 §2). This store sits behind the gRPC OTA
// handlers (CheckForUpdate/DownloadUpdate) as well as the admin Settings
// surface — neither is a hot per-heartbeat path the way OffloadTargetStore's
// fire_event is, so one ordinary CRUD budget covers both. Construction is
// the only unbounded acquire.
constexpr std::chrono::milliseconds kAcquireTimeout{2000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE update_packages ("
         "  platform    TEXT    NOT NULL,"
         "  arch        TEXT    NOT NULL,"
         "  version     TEXT    NOT NULL,"
         "  sha256      TEXT    NOT NULL,"
         "  filename    TEXT    NOT NULL,"
         "  mandatory   BOOLEAN NOT NULL DEFAULT FALSE,"
         "  rollout_pct INTEGER NOT NULL DEFAULT 100,"
         // Kept TEXT (ISO-8601), not TIMESTAMPTZ -- byte-identical round-trip
         // with the pre-migration column, no caller changes (see the header
         // doc comment).
         "  uploaded_at TEXT    NOT NULL DEFAULT '',"
         "  file_size   BIGINT  NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (platform, arch, version)"
         ");"},
    };
    return kMigrations;
}

std::string col_str(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? std::string() : std::string(PQgetvalue(res, row, c));
}
bool col_bool(PGresult* res, int row, int c) {
    if (PQgetisnull(res, row, c))
        return false;
    const char* v = PQgetvalue(res, row, c);
    return v != nullptr && (v[0] == 't' || v[0] == 'T' || v[0] == '1');
}
int col_int(PGresult* res, int row, int c) {
    if (PQgetisnull(res, row, c))
        return 0;
    return std::atoi(PQgetvalue(res, row, c));
}
std::int64_t col_i64(PGresult* res, int row, int c) {
    if (PQgetisnull(res, row, c))
        return 0;
    return static_cast<std::int64_t>(std::strtoll(PQgetvalue(res, row, c), nullptr, 10));
}

UpdatePackage row_to_pkg(PGresult* res, int row) {
    UpdatePackage pkg;
    pkg.platform = col_str(res, row, 0);
    pkg.arch = col_str(res, row, 1);
    pkg.version = col_str(res, row, 2);
    pkg.sha256 = col_str(res, row, 3);
    pkg.filename = col_str(res, row, 4);
    pkg.mandatory = col_bool(res, row, 5);
    pkg.rollout_pct = col_int(res, row, 6);
    pkg.uploaded_at = col_str(res, row, 7);
    pkg.file_size = col_i64(res, row, 8);
    return pkg;
}

constexpr const char* kSelectCols = "platform, arch, version, sha256, filename, mandatory, "
                                    "rollout_pct, uploaded_at, file_size";

} // namespace

UpdateRegistry::UpdateRegistry(pg::PgPool& pool, const std::filesystem::path& update_dir)
    : pool_(pool), update_dir_(update_dir) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("UpdateRegistry: no database connection at construction ({})",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("UpdateRegistry: schema migration failed");
        return;
    }
    // Post-migration projection smoke-read (playbook "Runner guards" second-line-of-
    // defense): `run()`'s duplicate/non-monotonic version guard catches a version
    // collision baked into THIS binary's own migrations() vector, but not a version
    // already recorded in schema_meta by a DIFFERENT binary whose schema doesn't match
    // what this binary's runtime queries actually select (ApiTokenStore precedent).
    // Fail closed here rather than surfacing `undefined column` on whichever request
    // runs first.
    {
        const std::string smoke_sql =
            std::string("SELECT ") + kSelectCols + " FROM update_registry.update_packages LIMIT 0";
        pg::PgResult smoke =
            pg::exec_params(lease.get(), smoke_sql.c_str(), std::vector<std::string>{});
        if (smoke.status() != PGRES_TUPLES_OK) {
            spdlog::error("UpdateRegistry: post-migration schema projection check failed — "
                          "update_packages is missing an expected column: {}",
                          PQresultErrorMessage(smoke.get()));
            return;
        }
    }
    lease.reset();
    open_ = true;
    spdlog::info("UpdateRegistry initialized (schema {}) — fresh start, no legacy backfill",
                 kStoreName);
}

UpdateRegistry::~UpdateRegistry() = default;

void UpdateRegistry::upsert_package(const UpdatePackage& pkg) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::error("UpdateRegistry: upsert_package skipped, no connection in time ({})",
                      pool_.last_error());
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO update_registry.update_packages "
        "(platform, arch, version, sha256, filename, mandatory, rollout_pct, uploaded_at, "
        "file_size) "
        "VALUES ($1, $2, $3, $4, $5, $6::boolean, $7::int, $8, $9::bigint) "
        "ON CONFLICT (platform, arch, version) DO UPDATE SET "
        "  sha256 = EXCLUDED.sha256, filename = EXCLUDED.filename, "
        "  mandatory = EXCLUDED.mandatory, rollout_pct = EXCLUDED.rollout_pct, "
        "  uploaded_at = EXCLUDED.uploaded_at, file_size = EXCLUDED.file_size "
        "RETURNING platform",
        std::vector<std::string>{pkg.platform, pkg.arch, pkg.version, pkg.sha256, pkg.filename,
                                 pkg.mandatory ? "true" : "false",
                                 std::to_string(pkg.rollout_pct), pkg.uploaded_at,
                                 std::to_string(pkg.file_size)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("UpdateRegistry: upsert_package failed for {}/{}/{}: {}", pkg.platform,
                      pkg.arch, pkg.version, PQerrorMessage(lease.get()));
        return;
    }
    spdlog::info("UpdateRegistry: upserted package {}/{}/{} ({})", pkg.platform, pkg.arch,
                 pkg.version, pkg.filename);
}

void UpdateRegistry::remove_package(const std::string& platform, const std::string& arch,
                                    const std::string& version) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::error("UpdateRegistry: remove_package skipped, no connection in time ({})",
                      pool_.last_error());
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM update_registry.update_packages "
        "WHERE platform = $1 AND arch = $2 AND version = $3",
        std::vector<std::string>{platform, arch, version});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("UpdateRegistry: remove_package failed for {}/{}/{}: {}", platform, arch,
                      version, PQerrorMessage(lease.get()));
        return;
    }
    spdlog::info("UpdateRegistry: removed package {}/{}/{}", platform, arch, version);
}

std::vector<UpdatePackage> UpdateRegistry::list_packages() const {
    std::vector<UpdatePackage> packages;
    if (!open_)
        return packages;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::error("UpdateRegistry: list_packages skipped, no connection in time ({})",
                      pool_.last_error());
        return packages;
    }
    const std::string sql = std::string("SELECT ") + kSelectCols +
                            " FROM update_registry.update_packages ORDER BY platform, arch, "
                            "uploaded_at DESC";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("UpdateRegistry: list_packages failed: {}", PQerrorMessage(lease.get()));
        return packages;
    }
    const int rows = PQntuples(res.get());
    packages.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        packages.push_back(row_to_pkg(res.get(), i));
    return packages;
}

std::optional<UpdatePackage> UpdateRegistry::latest_for(const std::string& platform,
                                                        const std::string& arch) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        spdlog::error("UpdateRegistry: latest_for skipped, no connection in time ({})",
                      pool_.last_error());
        return std::nullopt;
    }
    const std::string sql = std::string("SELECT ") + kSelectCols +
                            " FROM update_registry.update_packages WHERE platform = $1 AND "
                            "arch = $2";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{platform, arch});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("UpdateRegistry: latest_for failed for {}/{}: {}", platform, arch,
                      PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::optional<UpdatePackage> best;
    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        UpdatePackage pkg = row_to_pkg(res.get(), i);
        if (!best.has_value() || compare_versions(pkg.version, best->version) > 0)
            best = std::move(pkg);
    }
    return best;
}

bool UpdateRegistry::is_eligible(const std::string& agent_id, int rollout_pct) {
    return rollout_pct >= 100 ||
           (std::hash<std::string>{}(agent_id) % 100) < static_cast<unsigned>(rollout_pct);
}

std::filesystem::path UpdateRegistry::binary_path(const UpdatePackage& pkg) const {
    return update_dir_ / pkg.filename;
}

} // namespace yuzu::server
