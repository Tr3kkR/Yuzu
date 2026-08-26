/**
 * test_webhook_store.cpp -- Unit tests for the Postgres-backed WebhookStore
 * (ADR-0057).
 *
 * Non-PG tests: pure-function coverage (hmac_sha256 against RFC 4231
 * vectors) that needs no database.
 *
 * [pg] tests: CRUD, cascade delete, and the ADR-0010 secrets seam
 * (has_secret invariant, tamper -> skip-not-unsigned-fire, no-secret ->
 * unsigned fire preserved).
 *
 * Most of the dedicated legacy-SQLite backfill TEST_CASE suite (2026-08-25)
 * was removed as part of a fresh-start-by-default policy change (ADR-0009
 * amendment). WebhookStore::migrate_from_sqlite()/migrate_from_sqlite_impl()
 * themselves are UNCHANGED and still present (their removal is a separate,
 * later step) -- this store shipped its backfill (PR #3563) the same day
 * the amendment landed, too late for the "don't build it" guidance to
 * reach it. Two cases were reinstated (governance flagged their removal):
 * the WAL/SHM sidecar 0600 permission-enforcement pair, both regression
 * tests for real findings from PR #3563's own governance/chaos rounds on
 * this still-live, secrets-adjacent boot path.
 */

#include "webhook_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "test_webhook_store_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::test::WebhookStorePg;

// ── hmac_sha256 — pure function, no database needed ────────────────────────
// RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?"

TEST_CASE("WebhookStore::hmac_sha256 matches RFC 4231 test vector 2", "[webhook_store]") {
    const auto sig = WebhookStore::hmac_sha256("Jefe", "what do ya want for nothing?");
    CHECK(sig == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST_CASE("WebhookStore::hmac_sha256 is deterministic and key-sensitive", "[webhook_store]") {
    const auto a = WebhookStore::hmac_sha256("secret-a", "payload");
    const auto b = WebhookStore::hmac_sha256("secret-a", "payload");
    const auto c = WebhookStore::hmac_sha256("secret-b", "payload");
    CHECK(a == b);
    CHECK(a != c);
    CHECK(a.size() == 64); // 32 bytes, hex-encoded
}

// ── [pg] fixture ─────────────────────────────────────────────────────────
//
// WebhookStorePg (skip-if-no-PG, self-contained ephemeral DB + FileKeyProvider
// + SecretCodec + WebhookStore) lives in test_webhook_store_pg_helper.hpp —
// shared with test_agent_service_impl.cpp's EventSinkScope so both files
// derive the FileKeyProvider/SecretCodec/WebhookStore wiring exactly once
// (docs/postgres-store-playbook.md's test-file-drift note).

namespace {

/// Writes a minimal legacy `webhooks.db` (+ optional `webhook_deliveries`)
/// SQLite file at `path`, matching the pre-migration SQLite schema exactly.
/// Reinstated for the two WAL/SHM 0600-enforcement regression tests below
/// only — governance flagged their removal, since they're real regression
/// tests for findings from PR #3563's own review, on a still-live path.
class LegacyWebhookDb {
public:
    struct Row {
        std::int64_t id;
        std::string url;
        std::string event_types;
        std::string secret; // plaintext, as the legacy schema stored it
        bool enabled{true};
        std::int64_t created_at;
    };
    struct DeliveryRow {
        std::int64_t id;
        std::int64_t webhook_id;
        std::string event_type;
        std::string payload;
        int status_code{200};
        std::int64_t delivered_at;
        std::string error;
    };

    explicit LegacyWebhookDb(const std::filesystem::path& path) : path_(path) {
        REQUIRE(sqlite3_open(path.string().c_str(), &db_) == SQLITE_OK);
        REQUIRE(sqlite3_exec(db_,
                             "CREATE TABLE webhooks (id INTEGER PRIMARY KEY, url TEXT NOT NULL, "
                             "event_types TEXT NOT NULL DEFAULT '*', secret TEXT NOT NULL "
                             "DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, created_at "
                             "INTEGER NOT NULL);"
                             "CREATE TABLE webhook_deliveries (id INTEGER PRIMARY KEY, "
                             "webhook_id INTEGER NOT NULL, event_type TEXT NOT NULL, payload "
                             "TEXT NOT NULL, status_code INTEGER NOT NULL DEFAULT 0, "
                             "delivered_at INTEGER NOT NULL, error TEXT NOT NULL DEFAULT '');",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }
    ~LegacyWebhookDb() {
        if (db_)
            sqlite3_close(db_);
    }
    LegacyWebhookDb(const LegacyWebhookDb&) = delete;
    LegacyWebhookDb& operator=(const LegacyWebhookDb&) = delete;

    void insert(const Row& r) {
        char* sql = sqlite3_mprintf(
            "INSERT INTO webhooks (id,url,event_types,secret,enabled,created_at) VALUES "
            "(%lld,%Q,%Q,%Q,%d,%lld)",
            static_cast<long long>(r.id), r.url.c_str(), r.event_types.c_str(),
            r.secret.c_str(), r.enabled ? 1 : 0, static_cast<long long>(r.created_at));
        REQUIRE(sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_free(sql);
    }
    void insert(const DeliveryRow& d) {
        char* sql = sqlite3_mprintf(
            "INSERT INTO webhook_deliveries "
            "(id,webhook_id,event_type,payload,status_code,delivered_at,error) VALUES "
            "(%lld,%lld,%Q,%Q,%d,%lld,%Q)",
            static_cast<long long>(d.id), static_cast<long long>(d.webhook_id),
            d.event_type.c_str(), d.payload.c_str(), d.status_code,
            static_cast<long long>(d.delivered_at), d.error.c_str());
        REQUIRE(sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_free(sql);
    }

    void close() {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

private:
    std::filesystem::path path_;
    sqlite3* db_{nullptr};
};

/// Polls get_deliveries() until at least `min_count` rows are present or
/// `timeout` elapses — deliveries land asynchronously on the worker pool.
std::vector<WebhookDelivery> wait_for_deliveries(WebhookStore& store, std::int64_t webhook_id,
                                                 std::size_t min_count,
                                                 std::chrono::milliseconds timeout =
                                                     std::chrono::seconds(5)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        auto d = store.get_deliveries(webhook_id, 50);
        if (d.size() >= min_count || std::chrono::steady_clock::now() >= deadline)
            return d;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

} // namespace

// ── CRUD ─────────────────────────────────────────────────────────────────

TEST_CASE("WebhookStore[pg]: create and list webhook", "[webhook_store][pg]") {
    WebhookStorePg store;

    auto id = store->create_webhook("https://example.com/hook", "agent.registered", "secret123");
    REQUIRE(id.has_value());
    CHECK(*id > 0);

    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    REQUIRE(hooks->size() == 1);
    CHECK((*hooks)[0].url == "https://example.com/hook");
    CHECK((*hooks)[0].event_types == "agent.registered");
    CHECK((*hooks)[0].has_secret == true); // list() never exposes the secret itself
    CHECK((*hooks)[0].enabled == true);
    CHECK((*hooks)[0].id == *id);
}

TEST_CASE("WebhookStore[pg]: create without a secret sets has_secret=false",
         "[webhook_store][pg]") {
    WebhookStorePg store;

    auto id = store->create_webhook("https://example.com/hook", "*", /*secret=*/"");
    REQUIRE(id.has_value());

    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    REQUIRE(hooks->size() == 1);
    CHECK((*hooks)[0].has_secret == false);
}

TEST_CASE("WebhookStore[pg]: multiple webhooks", "[webhook_store][pg]") {
    WebhookStorePg store;

    REQUIRE(store->create_webhook("https://a.com/hook", "agent.registered", "s1").has_value());
    REQUIRE(store->create_webhook("https://b.com/hook", "execution.completed", "s2").has_value());
    REQUIRE(store->create_webhook("http://c.com/hook", "agent.heartbeat", "s3").has_value());

    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    CHECK(hooks->size() == 3);
}

TEST_CASE("WebhookStore[pg]: delete webhook cascades its deliveries", "[webhook_store][pg]") {
    WebhookStorePg store;

    auto id = store->create_webhook("http://127.0.0.1:1/h", "agent.registered", "secret");
    REQUIRE(id.has_value());

    store->fire_event("agent.registered", R"({"k":"v"})");
    auto before = wait_for_deliveries(*store, *id, 1);
    REQUIRE(before.size() == 1);

    auto deleted = store->delete_webhook(*id);
    REQUIRE(deleted.has_value());
    CHECK(*deleted == true);

    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    CHECK(hooks->empty());
    // ON DELETE CASCADE — the delivery log for the deleted webhook is gone too.
    CHECK(store->get_deliveries(*id).empty());
}

TEST_CASE("WebhookStore[pg]: delete nonexistent webhook returns false, not an error",
         "[webhook_store][pg]") {
    WebhookStorePg store;

    auto deleted = store->delete_webhook(99999);
    REQUIRE(deleted.has_value());
    CHECK(*deleted == false);
}

TEST_CASE("WebhookStore[pg]: rejects invalid URL scheme with a typed error",
         "[webhook_store][pg][security]") {
    WebhookStorePg store;

    auto r1 = store->create_webhook("ftp://example.com/hook", "agent.registered", "secret");
    REQUIRE_FALSE(r1.has_value());
    CHECK(r1.error() == WebhookWriteError::invalid_url);

    auto r2 = store->create_webhook("javascript:alert(1)", "agent.registered", "secret");
    REQUIRE_FALSE(r2.has_value());
    CHECK(r2.error() == WebhookWriteError::invalid_url);

    auto r3 = store->create_webhook("", "agent.registered", "secret");
    REQUIRE_FALSE(r3.has_value());
    CHECK(r3.error() == WebhookWriteError::invalid_url);

    auto r4 = store->create_webhook("https://example.com/hook", "agent.registered", "secret");
    REQUIRE(r4.has_value());
}

TEST_CASE("WebhookStore[pg]: empty store returns empty list, not degraded",
         "[webhook_store][pg]") {
    WebhookStorePg store;
    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    CHECK(hooks->empty());
}

TEST_CASE("WebhookStore[pg]: get_deliveries on empty webhook returns empty",
         "[webhook_store][pg]") {
    WebhookStorePg store;
    auto id = store->create_webhook("https://example.com/hook", "agent.registered", "secret");
    REQUIRE(id.has_value());
    CHECK(store->get_deliveries(*id).empty());
}

// ── ADR-0010 secrets seam ────────────────────────────────────────────────

TEST_CASE("WebhookStore[pg]: delivery with no secret configured fires unsigned (not skipped)",
         "[webhook_store][pg][security]") {
    WebhookStorePg store;
    auto id = store->create_webhook("http://127.0.0.1:1/h", "agent.registered", /*secret=*/"");
    REQUIRE(id.has_value());

    store->fire_event("agent.registered", R"({"k":"v"})");
    auto deliveries = wait_for_deliveries(*store, *id, 1);
    REQUIRE(deliveries.size() == 1);
    // Port 1 always refuses — the connection attempt itself was made
    // (unsigned), proving the has_secret=false path never routes through
    // the decrypt-skip branch.
    CHECK(deliveries[0].error == "connection_failed");
}

TEST_CASE("WebhookStore[pg]: fire_event never dispatches to a disabled webhook",
         "[webhook_store][pg]") {
    // gov Gate 3 quality-engineer (PR #3563 full-PR review): fire_event's
    // routing predicate (event_matches + enabled) was never exercised
    // end-to-end by any prior round — every delivery test fired an event
    // whose type exactly matched the sole enabled webhook. This proves the
    // enabled=false exclusion specifically.
    WebhookStorePg store;
    auto disabled_id = store->create_webhook("http://127.0.0.1:1/disabled", "agent.registered",
                                             /*secret=*/"", /*enabled=*/false);
    REQUIRE(disabled_id.has_value());
    auto control_id =
        store->create_webhook("http://127.0.0.1:1/control", "agent.registered", /*secret=*/"");
    REQUIRE(control_id.has_value());

    store->fire_event("agent.registered", R"({"k":"v"})");
    // Synchronize on the ENABLED control webhook's delivery completing —
    // both dispatch through the same worker pool, so once the control is
    // done the disabled one (if it had erroneously fired) would be too.
    auto control_deliveries = wait_for_deliveries(*store, *control_id, 1);
    REQUIRE(control_deliveries.size() == 1);

    auto disabled_deliveries = store->get_deliveries(*disabled_id, 50);
    CHECK(disabled_deliveries.empty());
}

TEST_CASE("WebhookStore[pg]: fire_event never dispatches on an event-type mismatch",
         "[webhook_store][pg]") {
    // Same rationale as the disabled-webhook test above — proves the
    // event_matches() half of the routing predicate.
    WebhookStorePg store;
    auto mismatched_id = store->create_webhook("http://127.0.0.1:1/mismatched",
                                               "policy.violation", /*secret=*/"");
    REQUIRE(mismatched_id.has_value());
    auto control_id =
        store->create_webhook("http://127.0.0.1:1/control", "agent.registered", /*secret=*/"");
    REQUIRE(control_id.has_value());

    store->fire_event("agent.registered", R"({"k":"v"})");
    auto control_deliveries = wait_for_deliveries(*store, *control_id, 1);
    REQUIRE(control_deliveries.size() == 1);

    auto mismatched_deliveries = store->get_deliveries(*mismatched_id, 50);
    CHECK(mismatched_deliveries.empty());
}

TEST_CASE("WebhookStore[pg]: a tampered secret blob is skipped, never fired unsigned",
         "[webhook_store][pg][security]") {
    WebhookStorePg store;
    auto id = store->create_webhook("http://127.0.0.1:1/h", "agent.registered", "real-secret");
    REQUIRE(id.has_value());

    // Corrupt the stored ciphertext via a second connection — flips the LSB
    // of the last byte (squarely inside the ciphertext region, well past
    // the fixed 93-byte header), so decrypt() must fail its GCM tag check.
    {
        auto lease = store.pool().acquire();
        REQUIRE(lease);
        auto res = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE webhook_store.webhooks SET secret = set_byte(secret, "
            "octet_length(secret)-1, get_byte(secret, octet_length(secret)-1) # 1) "
            "WHERE id = $1::bigint",
            std::vector<std::string>{std::to_string(*id)});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    store->fire_event("agent.registered", R"({"k":"v"})");
    auto deliveries = wait_for_deliveries(*store, *id, 1);
    REQUIRE(deliveries.size() == 1);
    // NEVER "connection_failed" here — a decrypt failure must skip the
    // delivery entirely (headline rule, ADR-0057/ADR-0010), not fall
    // through to an unsigned (or any) network attempt.
    CHECK(deliveries[0].error == "secret_unavailable");
    CHECK(deliveries[0].status_code == 0);

    // gov Gate 3 quality-engineer: the delivery-outcome assertions above
    // prove ONLY that some decrypt failure occurred — they can't
    // distinguish this tamper from e.g. a malformed_blob false-pass. Assert
    // the codec's own internal counter to prove tag_mismatch specifically
    // was hit, confirming the byte flip landed inside the GCM tag/
    // ciphertext region (kCiphertextOffset=93, well past the 11-byte
    // plaintext here) rather than some other failure class.
    bool saw_tag_mismatch = false;
    for (const auto& [key, count] : store.codec().decrypt_failure_counts()) {
        const auto& [codec_store, cls] = key;
        if (codec_store == "webhook_store" &&
            cls == yuzu::server::pg::SecretCodec::FailureClass::tag_mismatch && count > 0)
            saw_tag_mismatch = true;
    }
    CHECK(saw_tag_mismatch);
}

TEST_CASE("WebhookStore[pg]: NULL secret with has_secret=true is a hard decrypt error",
         "[webhook_store][pg][security]") {
    WebhookStorePg store;
    auto id = store->create_webhook("http://127.0.0.1:1/h", "agent.registered", "real-secret");
    REQUIRE(id.has_value());

    // ADR-0010 §Decision-1 anti-downgrade: a row whose has_secret=true but
    // whose blob is NULL must be a hard error, never silently read as
    // "no auth". The CHECK constraint forbids writing this state through
    // the store's own API — simulate an out-of-band corruption (a hand
    // edit, a botched migration) that produced it anyway, bypassing the
    // constraint via a direct constraint-violating attempt, and confirm
    // Postgres itself refuses it (defence-in-depth is real, not just
    // asserted in a comment).
    auto lease = store.pool().acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(), "UPDATE webhook_store.webhooks SET secret = NULL WHERE id = $1::bigint",
        std::vector<std::string>{std::to_string(*id)});
    CHECK(res.status() == PGRES_FATAL_ERROR); // CHECK constraint violation
}

TEST_CASE("WebhookStore[pg]: a non-NULL secret with has_secret=false is also a CHECK violation",
         "[webhook_store][pg][security]") {
    // gov Gate 3 quality-engineer: the CHECK constraint
    // (webhook_store.cpp's migration DDL) is a symmetric XNOR —
    // (has_secret AND secret IS NOT NULL) OR (NOT has_secret AND secret IS
    // NULL) — and the sibling test above only exercised one arm. Prove the
    // other: has_secret=false with a non-NULL secret is refused too, not
    // just silently ignored.
    WebhookStorePg store;
    auto id = store->create_webhook("http://127.0.0.1:1/h", "agent.registered", /*secret=*/"");
    REQUIRE(id.has_value());

    auto lease = store.pool().acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(),
        "UPDATE webhook_store.webhooks SET secret = decode('00','hex') WHERE id = $1::bigint",
        std::vector<std::string>{std::to_string(*id)});
    CHECK(res.status() == PGRES_FATAL_ERROR); // CHECK constraint violation
}

// ── Legacy-SQLite backfill: WAL/SHM sidecar permission enforcement ─────────
// Reinstated (governance flagged their removal from the 2026-08-25
// fresh-start-by-default sweep): both are regression tests for real
// findings against PR #3563's own review rounds, on WebhookStore's
// still-live, secrets-adjacent `migrate_from_sqlite()` boot path.

#ifndef _WIN32
TEST_CASE("WebhookStore[pg]: backfill restricts WAL/SHM sidecars to 0600, not just the main file",
         "[webhook_store][pg]") {
    // gov external-review finding (PR #3563): move_legacy_aside chmod'd only
    // the moved-aside main file — the -wal/-shm sidecars, which can carry
    // the same PLAINTEXT secret pages the main file's own read-time force
    // exists to protect, were renamed but left at whatever mode they
    // already had. Prove both sidecars land at owner-only after backfill.
    WebhookStorePg store;
    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_webhook_legacy_wal") += ".db";
    {
        LegacyWebhookDb legacy(legacy_path);
        legacy.insert({.id = 1,
                      .url = "https://example.com/hook",
                      .event_types = "*",
                      .secret = "s",
                      .enabled = true,
                      .created_at = 1700000000});
    }
    // Simulate an unclean-shutdown leftover: dummy sidecar files, group/
    // world-readable, sitting beside the legacy db. Content is irrelevant —
    // move_legacy_aside only needs to see them exist at the expected path.
    for (const char* suffix : {"-wal", "-shm"}) {
        auto side = legacy_path;
        side += suffix;
        std::ofstream(side) << "dummy-sidecar-content";
        std::filesystem::permissions(side,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write |
                                         std::filesystem::perms::group_read |
                                         std::filesystem::perms::others_read,
                                     std::filesystem::perm_options::replace);
    }

    REQUIRE(store->migrate_from_sqlite(legacy_path));

    std::filesystem::path moved_main, moved_wal, moved_shm;
    for (const auto& entry :
        std::filesystem::directory_iterator(legacy_path.parent_path())) {
        const auto s = entry.path().string();
        if (!s.starts_with(legacy_path.string() + ".migrated-"))
            continue;
        if (s.ends_with("-wal"))
            moved_wal = entry.path();
        else if (s.ends_with("-shm"))
            moved_shm = entry.path();
        else
            moved_main = entry.path();
    }
    REQUIRE_FALSE(moved_main.empty());
    REQUIRE_FALSE(moved_wal.empty());
    REQUIRE_FALSE(moved_shm.empty());

    const auto owner_only =
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    for (const auto& p : {moved_main, moved_wal, moved_shm}) {
        std::error_code st_ec;
        const auto perms = std::filesystem::status(p, st_ec).permissions();
        REQUIRE_FALSE(st_ec);
        CHECK((perms & std::filesystem::perms::mask) == owner_only);
    }
}

TEST_CASE("WebhookStore[pg]: a sidecar that fails to move is still 0600 at its original path, "
         "and doesn't block the main file from moving",
         "[webhook_store][pg]") {
    // gov Gate 5 chaos analysis CH-1 (PR #3563 fix round): force the `-wal`
    // rename to fail by pre-occupying its target path with a non-empty
    // directory (POSIX rename() onto a non-empty directory fails
    // ENOTEMPTY/EISDIR). Proves two independent claims: (1) the read-time
    // 0600 force in migrate_from_sqlite_impl protects a sidecar regardless
    // of whether move_legacy_aside later manages to relocate it; (2) one
    // sidecar's rename failure doesn't prevent the main file (or the OTHER
    // sidecar) from moving and being chmod'd normally.
    //
    // `aside`'s suffix comes from `now_epoch()` (1s-resolution wall clock)
    // read INSIDE move_legacy_aside, which this test can't observe
    // directly — pre-occupy a small window of candidate seconds around
    // "now" so a slow test runner can't miss the real timestamp.
    WebhookStorePg store;
    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_webhook_legacy_wal_fail") += ".db";
    {
        LegacyWebhookDb legacy(legacy_path);
        legacy.insert({.id = 1,
                      .url = "https://example.com/hook",
                      .event_types = "*",
                      .secret = "s",
                      .enabled = true,
                      .created_at = 1700000000});
    }
    for (const char* suffix : {"-wal", "-shm"}) {
        auto side = legacy_path;
        side += suffix;
        std::ofstream(side) << "dummy-sidecar-content";
    }

    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    std::vector<std::filesystem::path> decoy_dirs;
    // gov Gate 8 (PR #3563 fix round): a generous window — creating a few
    // dozen empty decoy directories is essentially free, and widening it
    // costs nothing but removes a real (if unlikely) flake source on a
    // heavily contended runner where several seconds could elapse between
    // this read and move_legacy_aside's own now_epoch() call.
    for (auto t = now - 2; t <= now + 60; ++t) {
        auto decoy = legacy_path;
        decoy += ".migrated-" + std::to_string(t) + "-wal";
        std::error_code mk_ec;
        if (std::filesystem::create_directory(decoy, mk_ec) && !mk_ec) {
            std::ofstream(decoy / "occupied") << "blocks the rename target";
            decoy_dirs.push_back(decoy);
        }
    }
    REQUIRE_FALSE(decoy_dirs.empty());

    REQUIRE(store->migrate_from_sqlite(legacy_path)); // non-fatal: still succeeds

    // The original `-wal` file must still exist at its ORIGINAL path (the
    // rename never succeeded) and must be 0600 from the read-time force —
    // independent of the later move that failed for it.
    auto orphan_wal = legacy_path;
    orphan_wal += "-wal";
    REQUIRE(std::filesystem::exists(orphan_wal));
    {
        std::error_code st_ec;
        const auto perms = std::filesystem::status(orphan_wal, st_ec).permissions();
        REQUIRE_FALSE(st_ec);
        CHECK((perms & std::filesystem::perms::mask) ==
             (std::filesystem::perms::owner_read | std::filesystem::perms::owner_write));
    }

    // The main file and the (unobstructed) -shm sidecar must still have
    // moved and been chmod'd normally — one sidecar's failure doesn't take
    // the rest down with it.
    std::filesystem::path moved_main, moved_shm;
    for (const auto& entry :
        std::filesystem::directory_iterator(legacy_path.parent_path())) {
        const auto s = entry.path().string();
        if (!s.starts_with(legacy_path.string() + ".migrated-") || s.ends_with("-wal"))
            continue;
        if (s.ends_with("-shm"))
            moved_shm = entry.path();
        else
            moved_main = entry.path();
    }
    REQUIRE_FALSE(moved_main.empty());
    REQUIRE_FALSE(moved_shm.empty());
    const auto owner_only2 =
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    for (const auto& p : {moved_main, moved_shm}) {
        std::error_code st_ec;
        const auto perms = std::filesystem::status(p, st_ec).permissions();
        REQUIRE_FALSE(st_ec);
        CHECK((perms & std::filesystem::perms::mask) == owner_only2);
    }

    // A second boot against the (now-nonexistent) original main path must
    // not disturb the orphaned sidecar's permissions — it's never
    // rediscovered once the main file is gone.
    REQUIRE(store->migrate_from_sqlite(legacy_path));
    std::error_code st_ec2;
    const auto perms2 = std::filesystem::status(orphan_wal, st_ec2).permissions();
    REQUIRE_FALSE(st_ec2);
    CHECK((perms2 & std::filesystem::perms::mask) == owner_only2);
}
#endif

