// AppUsageStore tests (wave 7 PR7.2): the born-on-Postgres per-executable
// last-used store — migration-at-construction, the raw-blob hash-skip
// trichotomy primitives (stored/touched/need-full), atomic full-replace, the
// staleness read, the decommission delete_agent (two-table, one txn, the
// hash-skip repopulation trap), and the authoritative-read posture
// (nullopt/kDegraded on a degrade, never a silent empty).

#include <catch2/catch_test_macros.hpp>

#include "app_usage_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using yuzu::server::AgentLastUsedRow;
using yuzu::server::AppUsageReadError;
using yuzu::server::AppUsageStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

AgentLastUsedRow row(const std::string& exe_key, std::int64_t first_seen, std::int64_t last_seen,
                     std::int64_t run_count = 1, std::int64_t total_seconds = 60) {
    AgentLastUsedRow r;
    r.exe_key = exe_key;
    r.first_seen = first_seen;
    r.last_seen = last_seen;
    r.run_count_30d = run_count;
    r.total_seconds_30d = total_seconds;
    r.collected_at = last_seen;
    return r;
}

} // namespace

TEST_CASE("AppUsageStore: opens and migrates on a fresh database", "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    CHECK(store.is_open());
}

TEST_CASE("AppUsageStore: stored_hash on a cold cache is a value holding nullopt",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());
    auto result = store.stored_hash("never-seen-agent");
    REQUIRE(result.has_value());  // not degraded
    CHECK_FALSE(result->has_value()); // cold cache
}

TEST_CASE("AppUsageStore: replace_agent_last_used round-trips rows and the raw hash",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());

    const std::string agent = "agent-1";
    std::vector<AgentLastUsedRow> rows = {row("chrome.exe", 1699000000, 1700000500, 12, 43200),
                                          row("word.exe", 1698000000, 1700000600, 3, 900)};
    REQUIRE(store.replace_agent_last_used(agent, rows, "hash-v1"));

    auto stored = store.stored_hash(agent);
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == "hash-v1");

    auto got = store.get_agent_last_used(agent);
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 2);
    // exe_key-sorted.
    CHECK((*got)[0].exe_key == "chrome.exe");
    CHECK((*got)[0].run_count_30d == 12);
    CHECK((*got)[0].total_seconds_30d == 43200);
    CHECK((*got)[1].exe_key == "word.exe");
}

TEST_CASE("AppUsageStore: a second replace supersedes the first (old rows gone)",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());

    const std::string agent = "agent-2";
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500)}, "hash-v1"));
    REQUIRE(store.replace_agent_last_used(agent, {row("word.exe", 1698000000, 1700000600)},
                                          "hash-v2"));

    auto got = store.get_agent_last_used(agent);
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    CHECK((*got)[0].exe_key == "word.exe");

    auto stored = store.stored_hash(agent);
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == "hash-v2");
}

TEST_CASE("AppUsageStore: an empty rows replace is a legitimate replace-to-empty",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());

    const std::string agent = "agent-3";
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500)}, "hash-v1"));
    REQUIRE(store.replace_agent_last_used(agent, {}, "hash-empty"));

    auto got = store.get_agent_last_used(agent);
    REQUIRE(got.has_value());
    CHECK(got->empty());
    auto stored = store.stored_hash(agent);
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == "hash-empty");
}

TEST_CASE("AppUsageStore: touch bumps freshness without altering child rows",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());

    const std::string agent = "agent-4";
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500)}, "hash-v1"));
    CHECK(store.touch(agent));

    auto stored = store.stored_hash(agent);
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == "hash-v1"); // touch never changes the hash
    auto got = store.get_agent_last_used(agent);
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
}

TEST_CASE("AppUsageStore: touch on a cold cache (no state row) fails",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());
    CHECK_FALSE(store.touch("never-seen-agent"));
}

TEST_CASE("AppUsageStore: get_agent_last_used with an empty agent_id is an empty value, "
          "not a degrade",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());
    auto got = store.get_agent_last_used("");
    REQUIRE(got.has_value());
    CHECK(got->empty());
}

// ── delete_agent: the two-table decommission, and the hash-skip repopulation
//    trap it must never reopen (PLAN-01 ruling (b)) ─────────────────────────

TEST_CASE("AppUsageStore: delete_agent guards an empty id and reports commit status",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.replace_agent_last_used(
        "agent-5", {row("chrome.exe", 1699000000, 1700000500)}, "hash-v1"));

    // Empty id: guarded — never a `WHERE agent_id = ''` — reports false, and
    // the real row is untouched.
    CHECK_FALSE(store.delete_agent(""));
    auto got = store.get_agent_last_used("agent-5");
    REQUIRE(got.has_value());
    CHECK_FALSE(got->empty());
}

TEST_CASE("AppUsageStore: delete_agent erases usage_state AND agent_last_used in one "
          "commit — pinned: post-delete stored_hash==nullopt and get_agent_last_used=={} "
          "(not nullopt)",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());

    const std::string agent = "agent-6";
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500), row("word.exe", 1698000000, 1700000600)},
        "hash-v1"));

    REQUIRE(store.delete_agent(agent));

    // The hash-skip repopulation trap (this package's spec): a delete that
    // cleared agent_last_used but left usage_state would make the still-
    // "enrolled" agent's next sync hash-only "touched", and the projection
    // would NEVER repopulate. Pin both halves of the erasure.
    auto stored = store.stored_hash(agent);
    REQUIRE(stored.has_value()); // not degraded
    CHECK_FALSE(stored->has_value()); // cold cache again — usage_state row is gone

    auto got = store.get_agent_last_used(agent);
    REQUIRE(got.has_value()); // AUTHORITATIVE: not a degrade
    CHECK(got->empty());      // empty VALUE (genuine zero rows), not nullopt

    // A real full resend after the delete must be accepted as a fresh cold
    // start (not "touched" against a resurrected hash).
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500)}, "hash-v2"));
    auto got2 = store.get_agent_last_used(agent);
    REQUIRE(got2.has_value());
    REQUIRE(got2->size() == 1);
}

TEST_CASE("AppUsageStore: delete_agent on an agent with no rows still commits",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());
    CHECK(store.delete_agent("agent-never-existed"));
}

TEST_CASE("AppUsageStore: count_stale_agents counts by last_seen threshold",
          "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.replace_agent_last_used(
        "agent-stale-1", {row("chrome.exe", 1699000000, 1700000500)}, "h1"));

    // Everything is fresh (last_seen == now()) relative to a threshold far in
    // the past, so the stale count is 0; relative to a threshold far in the
    // future, the freshly-written row counts as stale.
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    auto stale_past = store.count_stale_agents(now - 3600);
    REQUIRE(stale_past.has_value());
    CHECK(*stale_past == 0);

    auto stale_future = store.count_stale_agents(now + 3600);
    REQUIRE(stale_future.has_value());
    CHECK(*stale_future >= 1);
}

TEST_CASE("AppUsageStore: a store on an unreachable pool is closed and reads degrade",
          "[app_usage_store]") {
    PgPool pool{{.conninfo = "host=127.0.0.1 port=1 dbname=nope connect_timeout=1", .size = 1}};
    AppUsageStore store{pool};
    REQUIRE_FALSE(store.is_open());
    CHECK_FALSE(store.stored_hash("agent").has_value());
    CHECK_FALSE(store.touch("agent"));
    CHECK_FALSE(store.replace_agent_last_used("agent", {}, "h"));
    CHECK_FALSE(store.get_agent_last_used("agent").has_value());
    CHECK_FALSE(store.delete_agent("agent"));
    CHECK_FALSE(store.count_stale_agents(0).has_value());
}
