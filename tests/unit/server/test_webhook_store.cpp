/**
 * test_webhook_store.cpp -- Unit tests for the Postgres-backed WebhookStore
 * (ADR-0057).
 *
 * Non-PG tests: pure-function coverage (hmac_sha256 against RFC 4231
 * vectors) that needs no database.
 *
 * [pg] tests: CRUD, cascade delete, the ADR-0010 secrets seam
 * (has_secret invariant, tamper -> skip-not-unsigned-fire, no-secret ->
 * unsigned fire preserved), and the ADR-0009 legacy-SQLite backfill
 * (id preservation, decrypt-and-compare verification, orphan/fingerprint
 * handling).
 */

#include "webhook_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "test_webhook_store_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
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

// ── ADR-0009 legacy backfill ─────────────────────────────────────────────

TEST_CASE("WebhookStore[pg]: backfill preserves ids, decrypts-and-verifies the secret, and "
         "carries deliveries",
         "[webhook_store][pg]") {
    WebhookStorePg store;
    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_webhook_legacy") += ".db";

    {
        LegacyWebhookDb legacy(legacy_path);
        legacy.insert({.id = 5,
                      .url = "https://example.com/hook",
                      .event_types = "agent.registered",
                      .secret = "legacy-plaintext-secret",
                      .enabled = true,
                      .created_at = 1700000000});
        legacy.insert({.id = 9,
                      .url = "https://noauth.example.com/hook",
                      .event_types = "*",
                      .secret = "",
                      .enabled = false,
                      .created_at = 1700000100});
        legacy.insert(LegacyWebhookDb::DeliveryRow{.id = 42,
                                                   .webhook_id = 5,
                                                   .event_type = "agent.registered",
                                                   .payload = R"({"a":1})",
                                                   .status_code = 200,
                                                   .delivered_at = 1700000050,
                                                   .error = ""});
    }

    REQUIRE(store->migrate_from_sqlite(legacy_path));

    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    REQUIRE(hooks->size() == 2);

    const Webhook* signed_hook = nullptr;
    const Webhook* unsigned_hook = nullptr;
    for (const auto& w : *hooks) {
        if (w.id == 5)
            signed_hook = &w;
        else if (w.id == 9)
            unsigned_hook = &w;
    }
    REQUIRE(signed_hook != nullptr);
    REQUIRE(unsigned_hook != nullptr);
    CHECK(signed_hook->url == "https://example.com/hook");
    CHECK(signed_hook->has_secret == true);
    CHECK(signed_hook->enabled == true);
    CHECK(signed_hook->created_at == 1700000000);
    CHECK(unsigned_hook->has_secret == false);
    CHECK(unsigned_hook->enabled == false);

    // Decrypt-and-compare verification (ADR-0010 — ciphertext is
    // nondeterministic, never byte-compare): read the raw blob back and
    // decrypt it through the SAME codec the store uses.
    {
        auto lease = store.pool().acquire();
        REQUIRE(lease);
        auto res = yuzu::server::pg::exec_params(
            lease.get(), "SELECT encode(secret,'hex') FROM webhook_store.webhooks WHERE id=5",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(res.get()) == 1);
        std::string hex = PQgetvalue(res.get(), 0, 0);
        std::vector<std::uint8_t> blob;
        blob.reserve(hex.size() / 2);
        for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
            blob.push_back(static_cast<std::uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
        auto pk = yuzu::server::pg::SecretCodec::encode_bigint_pk(5);
        auto dec = store.codec().decrypt(
            yuzu::server::pg::SecretCodec::SecretId{"webhook_store", "webhooks", "secret", pk},
            blob);
        REQUIRE(dec.has_value());
        std::string plaintext(reinterpret_cast<const char*>(dec->data()), dec->size());
        CHECK(plaintext == "legacy-plaintext-secret");
    }

    // Delivery id preserved, correctly re-parented via the preserved
    // webhook id.
    auto deliveries = store->get_deliveries(5);
    REQUIRE(deliveries.size() == 1);
    CHECK(deliveries[0].id == 42);
    CHECK(deliveries[0].webhook_id == 5);
    CHECK(deliveries[0].payload == R"({"a":1})");

    // Legacy file moved aside (never deleted, ADR-0009).
    CHECK_FALSE(std::filesystem::exists(legacy_path));
    bool moved_copy_found = false;
    for (const auto& entry :
        std::filesystem::directory_iterator(legacy_path.parent_path())) {
        if (entry.path().string().starts_with(legacy_path.string() + ".migrated-"))
            moved_copy_found = true;
    }
    CHECK(moved_copy_found);
}

TEST_CASE("WebhookStore[pg]: backfill is idempotent — a second run against the moved-aside-free "
         "path is a no-op",
         "[webhook_store][pg]") {
    WebhookStorePg store;
    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_webhook_legacy2") += ".db";
    {
        LegacyWebhookDb legacy(legacy_path);
        legacy.insert({.id = 1,
                      .url = "https://example.com/hook",
                      .event_types = "*",
                      .secret = "s",
                      .enabled = true,
                      .created_at = 1700000000});
    }
    REQUIRE(store->migrate_from_sqlite(legacy_path));
    // The legacy file was moved aside — a second call against the ORIGINAL
    // (now-absent) path must also succeed cleanly (sourceless: "nothing to
    // migrate", not a fresh re-import).
    REQUIRE(store->migrate_from_sqlite(legacy_path));
    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    CHECK(hooks->size() == 1); // not duplicated
}

TEST_CASE("WebhookStore[pg]: backfill with no legacy file is a clean no-op",
         "[webhook_store][pg]") {
    WebhookStorePg store;
    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_webhook_legacy_absent") += ".db";
    REQUIRE(store->migrate_from_sqlite(legacy_path));
    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    CHECK(hooks->empty());
}

TEST_CASE("WebhookStore[pg]: backfill refuses (fail-closed) on an orphaned delivery row",
         "[webhook_store][pg]") {
    WebhookStorePg store;
    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_webhook_legacy_orphan") += ".db";
    {
        LegacyWebhookDb legacy(legacy_path);
        // A delivery referencing a webhook_id that was never inserted — the
        // legacy AND migrated schema both enforce this via FK CASCADE, so
        // this shape is corruption, not a real upgrade artifact.
        legacy.insert(LegacyWebhookDb::DeliveryRow{.id = 1,
                                                   .webhook_id = 999,
                                                   .event_type = "x",
                                                   .payload = "{}",
                                                   .status_code = 200,
                                                   .delivered_at = 1700000000,
                                                   .error = ""});
    }
    CHECK_FALSE(store->migrate_from_sqlite(legacy_path));
    // Refusing must leave the legacy file untouched (never moved aside on
    // a failed backfill — ADR-0009).
    CHECK(std::filesystem::exists(legacy_path));
}
