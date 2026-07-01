/**
 * test_result_set_maintenance.cpp — the result-set GC-sweep tick (Phase 15.G).
 *
 * run_result_set_gc() must: remove expired unpinned result sets (pinned sets
 * survive even past TTL), increment yuzu_result_set_gc_total by the count, and —
 * only when at least one set was swept — write a single aggregate
 * result_set.gc_sweep audit row under the __system__ principal. A null
 * AuditStore (audit-off) is tolerated.
 */

#include "result_set_maintenance.hpp"

#include "audit_store.hpp"
#include "result_set_store.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <sqlite3.h>

#include <string>

#include "../test_helpers.hpp"

using namespace yuzu::server;
using yuzu::test::TempDbFile;

namespace {

CreateRequest req(const std::string& owner, const std::string& name = "") {
    CreateRequest r;
    r.owner_principal = owner;
    r.name = name;
    r.source_kind = std::string(source_kind::kManualCurate);
    r.source_payload = "{}";
    return r;
}

// Backdate a set's TTL on a second connection so gc_sweep() sees it as expired —
// the public API deliberately cannot produce a past TTL (mirrors the technique
// in test_result_set_store.cpp). created_at must stay <= ttl_at (schema CHECK),
// so age the row wholesale.
void expire(const std::filesystem::path& path, const std::string& id) {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(path.string().c_str(), &db) == SQLITE_OK);
    const std::string sql =
        "UPDATE result_sets SET created_at = 1, ttl_at = 2 WHERE id = '" + id + "';";
    const int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
    REQUIRE(rc == SQLITE_OK);
}

} // namespace

TEST_CASE("run_result_set_gc: sweeps expired unpinned, keeps pinned, audits + counts",
          "[result_set][gc][maintenance]") {
    TempDbFile rs_db{std::string_view{"rsmaint-rs-"}};
    TempDbFile audit_db{std::string_view{"rsmaint-audit-"}};
    ResultSetStore store(rs_db.path);
    REQUIRE(store.is_open());
    AuditStore audit(audit_db.path, /*retention_days=*/365, /*cleanup_interval_min=*/0);
    REQUIRE(audit.is_open());
    yuzu::MetricsRegistry metrics;

    auto doomed = store.create_materialized(req("alice", "doomed"), {"a"});
    auto kept = store.create_materialized(req("alice", "kept"), {"b"});
    REQUIRE(doomed.has_value());
    REQUIRE(kept.has_value());
    REQUIRE(store.pin(kept->id).has_value());
    expire(rs_db.path, doomed->id);
    expire(rs_db.path, kept->id); // even past TTL, a pinned set must survive

    const int swept = run_result_set_gc(store, &audit, metrics);

    CHECK(swept == 1);
    CHECK_FALSE(store.get(doomed->id).has_value()); // swept
    CHECK(store.get(kept->id).has_value());         // pinned → survived
    CHECK(metrics.counter("yuzu_result_set_gc_total").value() == 1.0);

    AuditQuery q;
    q.action = "result_set.gc_sweep";
    auto rows = audit.query(q);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].principal == "__system__");
    CHECK(rows[0].result == "success");
    CHECK(rows[0].target_type == "ResultSet");
    CHECK(rows[0].detail == "count=1");
}

TEST_CASE("run_result_set_gc: nothing expired → no metric bump, no audit row",
          "[result_set][gc][maintenance]") {
    TempDbFile rs_db{std::string_view{"rsmaint-noop-rs-"}};
    TempDbFile audit_db{std::string_view{"rsmaint-noop-audit-"}};
    ResultSetStore store(rs_db.path);
    REQUIRE(store.is_open());
    AuditStore audit(audit_db.path, 365, 0);
    REQUIRE(audit.is_open());
    yuzu::MetricsRegistry metrics;

    auto fresh = store.create_materialized(req("alice", "fresh"), {"a"});
    REQUIRE(fresh.has_value()); // ttl_at = now + 1h, not expired

    CHECK(run_result_set_gc(store, &audit, metrics) == 0);
    CHECK(store.get(fresh->id).has_value());
    CHECK(metrics.counter("yuzu_result_set_gc_total").value() == 0.0);
    AuditQuery q;
    q.action = "result_set.gc_sweep";
    CHECK(audit.query(q).empty());
}

TEST_CASE("run_result_set_gc: null AuditStore still sweeps + counts (audit-off)",
          "[result_set][gc][maintenance]") {
    TempDbFile rs_db{std::string_view{"rsmaint-null-rs-"}};
    ResultSetStore store(rs_db.path);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;

    auto doomed = store.create_materialized(req("alice", "doomed"), {"a"});
    REQUIRE(doomed.has_value());
    expire(rs_db.path, doomed->id);

    CHECK(run_result_set_gc(store, /*audit=*/nullptr, metrics) == 1);
    CHECK_FALSE(store.get(doomed->id).has_value());
    CHECK(metrics.counter("yuzu_result_set_gc_total").value() == 1.0);
}
