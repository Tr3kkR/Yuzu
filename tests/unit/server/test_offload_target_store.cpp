/**
 * test_offload_target_store.cpp -- Unit tests for OffloadTargetStore
 * (Phase 8.3, #255; Postgres migration ADR-0059).
 *
 * Covers: open, create, list, get, get_by_name, delete, URL/name/batch
 * validation, delivery records, credential redaction, base64 encoding,
 * auth-type roundtrip, the ADR-0010 secrets seam (envelope round-trip,
 * decrypt-failure fail-closed, the has_credential/auth_credential CHECK
 * constraint), and the ADR-0009 legacy-SQLite backfill.
 *
 * PG-gated ([pg] tag): skips when YUZU_TEST_POSTGRES_DSN is unset, fails
 * when it is set but broken (docs/postgres-store-playbook.md §7).
 *
 * Network delivery (HTTP POST) is exercised against unreachable
 * loopback/reserved ports; the unit suite keeps the focus on store
 * invariants that the REST surface and the dispatch path rely on.
 */

#include "offload_target_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "test_offload_target_store_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include "../test_helpers.hpp"

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::test::OffloadTargetStorePg;

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: opens and migrates", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    REQUIRE(store->is_open());
}

// ── Create and list ────────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: create and list target", "[offload_store][pg]") {
    OffloadTargetStorePg store;

    auto result = store->create_target("siem-primary", "https://siem.example.com/ingest",
                                       OffloadAuthType::Bearer, "token-abc",
                                       "execution.completed", /*batch_size=*/1);
    REQUIRE(result.has_value());
    auto id = *result;
    CHECK(id > 0);

    auto targets = store->list();
    REQUIRE(targets.has_value());
    REQUIRE(targets->size() == 1);
    CHECK((*targets)[0].id == id);
    CHECK((*targets)[0].name == "siem-primary");
    CHECK((*targets)[0].url == "https://siem.example.com/ingest");
    CHECK((*targets)[0].auth_type == OffloadAuthType::Bearer);
    CHECK((*targets)[0].has_credential); // configured, but no plaintext exposed
    CHECK((*targets)[0].event_types == "execution.completed");
    CHECK((*targets)[0].batch_size == 1);
    CHECK((*targets)[0].enabled);
}

TEST_CASE("OffloadTargetStore[pg]: multiple targets", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    REQUIRE(store->create_target("a", "https://a.example.com/h", OffloadAuthType::None, "",
                                 "*")
                .has_value());
    REQUIRE(store->create_target("b", "http://b.example.com/h", OffloadAuthType::Basic,
                                 "user:pass", "agent.registered")
                .has_value());
    REQUIRE(store->create_target("c", "https://c.example.com/h", OffloadAuthType::Hmac,
                                 "shared-secret", "execution.completed", 5)
                .has_value());

    auto targets = store->list();
    REQUIRE(targets.has_value());
    REQUIRE(targets->size() == 3);
}

// ── get / get_by_name ──────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: get by id and name", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("named-target", "https://x.example.com/h",
                                       OffloadAuthType::None, "", "*");
    REQUIRE(result.has_value());
    auto id = *result;

    bool ok = true;
    auto by_id = store->get(id, &ok);
    REQUIRE(by_id.has_value());
    CHECK(ok);
    CHECK(by_id->name == "named-target");
    CHECK_FALSE(by_id->has_credential);

    auto by_name = store->get_by_name("named-target");
    REQUIRE(by_name.has_value());
    CHECK(by_name->id == id);

    ok = true;
    CHECK_FALSE(store->get(99999, &ok).has_value());
    CHECK(ok); // genuinely not found, not a degraded read
    CHECK_FALSE(store->get_by_name("nonexistent").has_value());
}

// ── Delete ─────────────────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: delete target", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("doomed", "https://x.example.com/h",
                                       OffloadAuthType::None, "", "*");
    REQUIRE(result.has_value());
    auto id = *result;
    auto listed = store->list();
    REQUIRE(listed.has_value());
    CHECK(listed->size() == 1);

    auto deleted = store->delete_target(id);
    REQUIRE(deleted.has_value());
    CHECK(*deleted);
    listed = store->list();
    REQUIRE(listed.has_value());
    CHECK(listed->empty());

    // Idempotent on missing — a business fact (false), not an error.
    deleted = store->delete_target(id);
    REQUIRE(deleted.has_value());
    CHECK_FALSE(*deleted);
}

// ── URL scheme validation ──────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: rejects invalid URL scheme", "[offload_store][pg][security]") {
    OffloadTargetStorePg store;

    auto ftp = store->create_target("ftp", "ftp://evil.example.com/h", OffloadAuthType::None, "",
                                    "*");
    REQUIRE_FALSE(ftp.has_value());
    CHECK(ftp.error() == OffloadWriteError::invalid_input);
    CHECK_FALSE(
        store->create_target("js", "javascript:alert(1)", OffloadAuthType::None, "", "*")
            .has_value());
    CHECK_FALSE(store->create_target("blank", "", OffloadAuthType::None, "", "*").has_value());

    CHECK(store->create_target("ok-https", "https://ok.example.com/h", OffloadAuthType::None, "",
                               "*")
              .has_value());
    CHECK(store->create_target("ok-http", "http://ok.example.com/h", OffloadAuthType::None, "",
                               "*")
              .has_value());
}

// ── Empty-name rejected ────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: rejects empty name", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("", "https://x.example.com/h", OffloadAuthType::None, "",
                                       "*");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == OffloadWriteError::invalid_input);
}

// ── Duplicate name rejected (UNIQUE constraint) ────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: rejects duplicate name", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    REQUIRE(
        store->create_target("dup", "https://a.example.com/h", OffloadAuthType::None, "", "*")
            .has_value());
    auto second =
        store->create_target("dup", "https://b.example.com/h", OffloadAuthType::None, "", "*");
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error() == OffloadWriteError::invalid_input);
}

// ── batch_size validation ──────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: rejects batch_size < 1", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    CHECK_FALSE(store->create_target("zero", "https://x.example.com/h", OffloadAuthType::None,
                                     "", "*", /*batch_size=*/0)
                    .has_value());
    CHECK_FALSE(store->create_target("neg", "https://x.example.com/h", OffloadAuthType::None, "",
                                     "*", /*batch_size=*/-1)
                    .has_value());

    CHECK(store->create_target("ok", "https://x.example.com/h", OffloadAuthType::None, "", "*",
                               /*batch_size=*/1)
              .has_value());
}

// ── Empty deliveries ───────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: get_deliveries on empty target returns empty",
          "[offload_store][pg]") {
    OffloadTargetStorePg store;
    auto result =
        store->create_target("t", "https://x.example.com/h", OffloadAuthType::None, "", "*");
    REQUIRE(result.has_value());
    CHECK(store->get_deliveries(*result).empty());
}

// ── Auth-type roundtrip (pure function — no store needed) ──────────────────

TEST_CASE("OffloadTargetStore: auth-type string roundtrip", "[offload_store]") {
    CHECK(offload_auth_type_to_string(OffloadAuthType::None) == "none");
    CHECK(offload_auth_type_to_string(OffloadAuthType::Bearer) == "bearer");
    CHECK(offload_auth_type_to_string(OffloadAuthType::Basic) == "basic");
    CHECK(offload_auth_type_to_string(OffloadAuthType::Hmac) == "hmac");

    CHECK(offload_auth_type_from_string("none") == OffloadAuthType::None);
    CHECK(offload_auth_type_from_string("bearer") == OffloadAuthType::Bearer);
    CHECK(offload_auth_type_from_string("basic") == OffloadAuthType::Basic);
    CHECK(offload_auth_type_from_string("hmac") == OffloadAuthType::Hmac);

    // Unknown / empty default to None — keeps the surface robust to wire
    // additions without crashing.
    CHECK(offload_auth_type_from_string("") == OffloadAuthType::None);
    CHECK(offload_auth_type_from_string("unknown") == OffloadAuthType::None);
}

// ── Base64 vectors (RFC 4648) — pure function ───────────────────────────────

TEST_CASE("OffloadTargetStore: base64 RFC 4648 vectors", "[offload_store]") {
    CHECK(OffloadTargetStore::base64_encode("") == "");
    CHECK(OffloadTargetStore::base64_encode("f") == "Zg==");
    CHECK(OffloadTargetStore::base64_encode("fo") == "Zm8=");
    CHECK(OffloadTargetStore::base64_encode("foo") == "Zm9v");
    CHECK(OffloadTargetStore::base64_encode("foob") == "Zm9vYg==");
    CHECK(OffloadTargetStore::base64_encode("fooba") == "Zm9vYmE=");
    CHECK(OffloadTargetStore::base64_encode("foobar") == "Zm9vYmFy");
    // Basic-auth shape — "user:pass" — exercised by the live header path.
    CHECK(OffloadTargetStore::base64_encode("user:pass") == "dXNlcjpwYXNz");
}

// ── HMAC-SHA256 known vector — pure function ────────────────────────────────

TEST_CASE("OffloadTargetStore: hmac_sha256 known vector", "[offload_store]") {
    // RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?".
    auto sig = OffloadTargetStore::hmac_sha256("Jefe", "what do ya want for nothing?");
    CHECK(sig == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

// ── fire_event matching: target_filter scoping ─────────────────────────────
//
// We can't test the network delivery in a unit test cleanly, but we CAN
// test that fire_event with a non-matching target_filter does NOT enqueue
// any deliveries by observing get_deliveries remains empty after the
// synchronous matching decision. With no network endpoint to hit, fire_event
// with batch_size=1 would otherwise produce a connection_failed delivery
// record — which is the signal that the dispatch loop ran. Filtered-out
// targets must produce nothing.

TEST_CASE("OffloadTargetStore[pg]: target_filter excludes non-matching names",
          "[offload_store][pg][filter]") {
    OffloadTargetStorePg store;
    auto id_a =
        store->create_target("alpha", "http://127.0.0.1:1/h", OffloadAuthType::None, "", "*");
    auto id_b =
        store->create_target("beta", "http://127.0.0.1:1/h", OffloadAuthType::None, "", "*");
    REQUIRE(id_a.has_value());
    REQUIRE(id_b.has_value());

    // Filter to a name that doesn't exist — neither target should fire.
    // The filter decision runs synchronously inside fire_event before any
    // delivery is queued, so the absence assertion is deterministic without
    // a sleep (qe-S2).
    store->fire_event("execution.completed", R"({"k":"v"})", {"gamma"});
    CHECK(store->get_deliveries(*id_a).empty());
    CHECK(store->get_deliveries(*id_b).empty());
}

// ── fire_event respects event_types filter ─────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: event_types filter excludes non-matching events",
          "[offload_store][pg][filter]") {
    OffloadTargetStorePg store;
    // Subscribed only to "agent.registered"
    auto result = store->create_target("only-reg", "http://127.0.0.1:1/h", OffloadAuthType::None,
                                       "", "agent.registered");
    REQUIRE(result.has_value());

    // Different event — filter is checked before dispatch (qe-S2).
    store->fire_event("execution.completed", R"({"k":"v"})");
    CHECK(store->get_deliveries(*result).empty());
}

// ── Disabled target is skipped ─────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: disabled target receives no events",
          "[offload_store][pg][filter]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("dormant", "http://127.0.0.1:1/h", OffloadAuthType::None,
                                       "", "*", /*batch_size=*/1, /*enabled=*/false);
    REQUIRE(result.has_value());

    // `WHERE enabled` filters disabled rows out of the scan synchronously
    // (the load-bearing partial index), so no dispatch runs and no sleep is
    // required (qe-S2).
    store->fire_event("execution.completed", R"({"k":"v"})");
    CHECK(store->get_deliveries(*result).empty());
}

// ── Batch accumulator: events buffer until threshold (qe-S3) ───────────────

TEST_CASE("OffloadTargetStore[pg]: batch_size > 1 accumulates without dispatch",
          "[offload_store][pg][batch]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("batched", "http://127.0.0.1:1/h", OffloadAuthType::None,
                                       "", "*", /*batch_size=*/3);
    REQUIRE(result.has_value());
    auto id = *result;

    // Fire two events — buffer holds them, no dispatch yet.
    store->fire_event("execution.completed", R"({"k":1})");
    store->fire_event("execution.completed", R"({"k":2})");
    CHECK(store->get_deliveries(id).empty());

    // Flush via the public flush_all() API rather than a third event so the
    // assertion is deterministic without a sleep on a worker-pool thread.
    store->flush_all();

    // Flush dispatch is async; poll up to 5s for the row to land.
    constexpr auto kPollDeadline = std::chrono::seconds(5);
    auto start = std::chrono::steady_clock::now();
    std::vector<OffloadDelivery> deliveries;
    while (std::chrono::steady_clock::now() - start < kPollDeadline) {
        deliveries = store->get_deliveries(id);
        if (!deliveries.empty())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    REQUIRE(deliveries.size() == 1);
    CHECK(deliveries[0].event_count == 2);
    // Body shape: {"events":[…]}
    CHECK(deliveries[0].payload.find("\"events\"") != std::string::npos);
}

// ── Control-byte rejection in name and url (round-3 residual finding) ─────

TEST_CASE("OffloadTargetStore[pg]: rejects name with control bytes",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    // Audit-row line-splitting via newline in name — DELETE handler
    // emits `name=<n> url=<u>` to the audit `detail` field.
    CHECK_FALSE(store->create_target("evil\nfake.event", "https://x.example.com/h",
                                     OffloadAuthType::None, "", "*")
                    .has_value());
    CHECK_FALSE(store->create_target(std::string("nul\0byte", 8), "https://x.example.com/h",
                                     OffloadAuthType::None, "", "*")
                    .has_value());
    CHECK(store->create_target("ok-name", "https://x.example.com/h", OffloadAuthType::None, "",
                               "*")
              .has_value());
}

TEST_CASE("OffloadTargetStore[pg]: rejects url with control bytes",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    CHECK_FALSE(store->create_target("a", "https://x.example.com/h\r\nX-Evil: 1",
                                     OffloadAuthType::None, "", "*")
                    .has_value());
    CHECK_FALSE(store->create_target("b", "https://x.example.com/h\nfoo", OffloadAuthType::None,
                                     "", "*")
                    .has_value());
    CHECK(store->create_target("c", "https://x.example.com/h", OffloadAuthType::None, "", "*")
              .has_value());
}

TEST_CASE("OffloadTargetStore[pg]: rejects event_types with control bytes",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    CHECK_FALSE(store->create_target("a", "https://x.example.com/h", OffloadAuthType::None, "",
                                     "exec\r\nX-Evil: 1")
                    .has_value());
    CHECK(store->create_target("b", "https://x.example.com/h", OffloadAuthType::None, "", "*")
              .has_value());
}

// ── CRLF / control-byte rejection in auth_credential (sec-H1) ──────────────

TEST_CASE("OffloadTargetStore[pg]: rejects auth_credential with control bytes",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;

    CHECK_FALSE(store->create_target("crlf-bearer", "https://x.example.com/h",
                                     OffloadAuthType::Bearer, "tok\r\nX-Evil: 1", "*")
                    .has_value());
    CHECK_FALSE(store->create_target("lf-only", "https://x.example.com/h", OffloadAuthType::Bearer,
                                     "tok\nfoo", "*")
                    .has_value());
    CHECK_FALSE(store->create_target("cr-only", "https://x.example.com/h", OffloadAuthType::Bearer,
                                     "tok\rfoo", "*")
                    .has_value());
    CHECK_FALSE(store->create_target("nul", "https://x.example.com/h", OffloadAuthType::Bearer,
                                     std::string("tok\0foo", 7), "*")
                    .has_value());
    // The same guard fires for Basic and HMAC as defence-in-depth even
    // though those auth types don't emit the credential verbatim.
    CHECK_FALSE(store->create_target("crlf-basic", "https://x.example.com/h",
                                     OffloadAuthType::Basic, "user\r\n:pass", "*")
                    .has_value());
    CHECK_FALSE(store->create_target("crlf-hmac", "https://x.example.com/h", OffloadAuthType::Hmac,
                                     "secret\nfoo", "*")
                    .has_value());

    CHECK(store->create_target("ok-bearer", "https://x.example.com/h", OffloadAuthType::Bearer,
                               "abcXYZ012!@#$%^&*()", "*")
              .has_value());
}

// ── Dispatch-time scheme guard (sec-M2) ────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: dispatch fires against a live target",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result =
        store->create_target("legit", "http://127.0.0.1:1/h", OffloadAuthType::None, "", "*");
    REQUIRE(result.has_value());
    auto id = *result;

    store->fire_event("execution.completed", R"({"k":"v"})");
    std::vector<OffloadDelivery> deliveries;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline) {
        deliveries = store->get_deliveries(id);
        if (!deliveries.empty())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    REQUIRE(deliveries.size() == 1);
    // Port 1 is reserved — the connection fails, proving the dispatch path
    // ran and reached the HTTP client.
    CHECK(deliveries[0].error == "connection_failed");
}

// ── ADR-0010 secrets seam ────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: delivery with no credential configured fires unsigned "
          "(not skipped)",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("no-cred", "http://127.0.0.1:1/h", OffloadAuthType::Bearer,
                                       /*auth_credential=*/"", "*");
    REQUIRE(result.has_value());
    auto id = *result;

    store->fire_event("execution.completed", R"({"k":"v"})");
    std::vector<OffloadDelivery> deliveries;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline) {
        deliveries = store->get_deliveries(id);
        if (!deliveries.empty())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    REQUIRE(deliveries.size() == 1);
    // connection_failed (not credential_unavailable) proves the connection
    // attempt was actually made — the has_credential=false path never
    // routes through the decrypt-skip branch.
    CHECK(deliveries[0].error == "connection_failed");
}

TEST_CASE("OffloadTargetStore[pg]: a tampered credential blob is skipped, never fired unsigned",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("tampered", "http://127.0.0.1:1/h", OffloadAuthType::Hmac,
                                       "shared-secret", "*");
    REQUIRE(result.has_value());
    auto id = *result;

    // Flip one bit of the stored ciphertext directly via a second PG
    // connection — chosen to land inside the ciphertext (past the 93-byte
    // blob header), so this is a tamper detection (GCM tag mismatch), not a
    // parse failure.
    {
        pg::PgConn conn{PQconnectdb(store.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult res = pg::exec_params(
            conn.get(),
            "UPDATE offload_target_store.offload_targets SET auth_credential = "
            "set_byte(auth_credential, octet_length(auth_credential)-1, "
            "get_byte(auth_credential, octet_length(auth_credential)-1) # 1) WHERE id = $1",
            std::vector<std::string>{std::to_string(id)});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    store->fire_event("execution.completed", R"({"k":"v"})");
    std::vector<OffloadDelivery> deliveries;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline) {
        deliveries = store->get_deliveries(id);
        if (!deliveries.empty())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    REQUIRE(deliveries.size() == 1);
    CHECK(deliveries[0].status_code == 0);
    CHECK(deliveries[0].error == "credential_unavailable"); // never "connection_failed"

    // Rule out a different failure class coincidentally passing.
    bool saw_tag_mismatch = false;
    for (const auto& [key, count] : store.codec().decrypt_failure_counts()) {
        const auto& [decrypt_store, cls] = key;
        if (decrypt_store == "offload_target_store" &&
            cls == pg::SecretCodec::FailureClass::tag_mismatch && count > 0)
            saw_tag_mismatch = true;
    }
    CHECK(saw_tag_mismatch);
}

TEST_CASE("OffloadTargetStore[pg]: NULL auth_credential with has_credential=true is a hard "
          "CHECK violation",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("checked", "https://x.example.com/h",
                                       OffloadAuthType::Bearer, "tok", "*");
    REQUIRE(result.has_value());

    pg::PgConn conn{PQconnectdb(store.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult res = pg::exec_params(
        conn.get(),
        "UPDATE offload_target_store.offload_targets SET auth_credential = NULL WHERE id = $1",
        std::vector<std::string>{std::to_string(*result)});
    // The CHECK constraint refuses this at the database level — the
    // anti-downgrade invariant is structural, not just app-level.
    CHECK(res.status() == PGRES_FATAL_ERROR);
}

TEST_CASE("OffloadTargetStore[pg]: a non-NULL auth_credential with has_credential=false is "
          "also a CHECK violation",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result =
        store->create_target("unchecked", "https://x.example.com/h", OffloadAuthType::None, "",
                             "*");
    REQUIRE(result.has_value());

    pg::PgConn conn{PQconnectdb(store.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult res = pg::exec_params(
        conn.get(),
        "UPDATE offload_target_store.offload_targets SET auth_credential = "
        "decode('00','hex') WHERE id = $1",
        std::vector<std::string>{std::to_string(*result)});
    CHECK(res.status() == PGRES_FATAL_ERROR);
}

// ── ADR-0009 legacy-SQLite backfill ─────────────────────────────────────────

namespace {

struct LegacyOffloadFixtureTarget {
    int64_t id{};
    std::string name, url, auth_type, credential, event_types;
    int batch_size{1};
    bool enabled{true};
    int64_t created_at{};
};

struct LegacyOffloadFixtureDelivery {
    int64_t id{}, target_id{};
    std::string event_type, payload, error;
    int event_count{1};
    int status_code{0};
    int64_t delivered_at{};
};

void write_legacy_offload_db(const std::filesystem::path& path,
                             const std::vector<LegacyOffloadFixtureTarget>& targets,
                             const std::vector<LegacyOffloadFixtureDelivery>& deliveries) {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(path.string().c_str(), &db) == SQLITE_OK);
    REQUIRE(sqlite3_exec(db,
                         "CREATE TABLE offload_targets (id INTEGER PRIMARY KEY, name TEXT, "
                         "url TEXT, auth_type TEXT, auth_credential TEXT, event_types TEXT, "
                         "batch_size INTEGER, enabled INTEGER, created_at INTEGER)",
                         nullptr, nullptr, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_exec(db,
                         "CREATE TABLE offload_deliveries (id INTEGER PRIMARY KEY, target_id "
                         "INTEGER, event_type TEXT, event_count INTEGER, payload TEXT, "
                         "status_code INTEGER, delivered_at INTEGER, error TEXT)",
                         nullptr, nullptr, nullptr) == SQLITE_OK);

    for (const auto& t : targets) {
        sqlite3_stmt* stmt = nullptr;
        REQUIRE(sqlite3_prepare_v2(db,
                                   "INSERT INTO offload_targets (id,name,url,auth_type,"
                                   "auth_credential,event_types,batch_size,enabled,created_at) "
                                   "VALUES (?,?,?,?,?,?,?,?,?)",
                                   -1, &stmt, nullptr) == SQLITE_OK);
        sqlite3_bind_int64(stmt, 1, t.id);
        sqlite3_bind_text(stmt, 2, t.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, t.url.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, t.auth_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, t.credential.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, t.event_types.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 7, t.batch_size);
        sqlite3_bind_int(stmt, 8, t.enabled ? 1 : 0);
        sqlite3_bind_int64(stmt, 9, t.created_at);
        REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
    }
    for (const auto& d : deliveries) {
        sqlite3_stmt* stmt = nullptr;
        REQUIRE(sqlite3_prepare_v2(db,
                                   "INSERT INTO offload_deliveries (id,target_id,event_type,"
                                   "event_count,payload,status_code,delivered_at,error) VALUES "
                                   "(?,?,?,?,?,?,?,?)",
                                   -1, &stmt, nullptr) == SQLITE_OK);
        sqlite3_bind_int64(stmt, 1, d.id);
        sqlite3_bind_int64(stmt, 2, d.target_id);
        sqlite3_bind_text(stmt, 3, d.event_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, d.event_count);
        sqlite3_bind_text(stmt, 5, d.payload.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 6, d.status_code);
        sqlite3_bind_int64(stmt, 7, d.delivered_at);
        sqlite3_bind_text(stmt, 8, d.error.c_str(), -1, SQLITE_TRANSIENT);
        REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
}

} // namespace

TEST_CASE("OffloadTargetStore[pg]: migrate_from_sqlite with no legacy file is a clean no-op",
          "[offload_store][pg][backfill]") {
    OffloadTargetStorePg store;
    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_offload_backfill_missing_");
    CHECK(store->migrate_from_sqlite(legacy_path));
    auto targets = store->list();
    REQUIRE(targets.has_value());
    CHECK(targets->empty());
}

TEST_CASE("OffloadTargetStore[pg]: migrate_from_sqlite backfills targets and deliveries, "
          "decrypts-and-verifies the credential",
          "[offload_store][pg][backfill]") {
    OffloadTargetStorePg store;
    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_offload_backfill_");

    LegacyOffloadFixtureTarget signed_target;
    signed_target.id = 1;
    signed_target.name = "legacy-signed";
    signed_target.url = "https://legacy.example.com/h";
    signed_target.auth_type = "hmac";
    signed_target.credential = "legacy-plaintext-secret";
    signed_target.event_types = "*";
    signed_target.batch_size = 1;
    signed_target.enabled = true;
    signed_target.created_at = 1700000000;

    LegacyOffloadFixtureTarget unsigned_target;
    unsigned_target.id = 2;
    unsigned_target.name = "legacy-unsigned";
    unsigned_target.url = "https://legacy2.example.com/h";
    unsigned_target.auth_type = "none";
    unsigned_target.event_types = "*";
    unsigned_target.batch_size = 1;
    unsigned_target.enabled = true;
    unsigned_target.created_at = 1700000001;

    LegacyOffloadFixtureDelivery delivery;
    delivery.id = 1;
    delivery.target_id = 1;
    delivery.event_type = "execution.completed";
    delivery.event_count = 1;
    delivery.payload = R"({"k":"v"})";
    delivery.status_code = 200;
    delivery.delivered_at = 1700000010;

    write_legacy_offload_db(legacy_path, {signed_target, unsigned_target}, {delivery});

    REQUIRE(store->migrate_from_sqlite(legacy_path));

    auto by_name_signed = store->get_by_name("legacy-signed");
    REQUIRE(by_name_signed.has_value());
    CHECK(by_name_signed->id == 1);
    CHECK(by_name_signed->has_credential);
    CHECK(by_name_signed->auth_type == OffloadAuthType::Hmac);

    auto by_name_unsigned = store->get_by_name("legacy-unsigned");
    REQUIRE(by_name_unsigned.has_value());
    CHECK_FALSE(by_name_unsigned->has_credential);

    // Ciphertext is nondeterministic (fresh DEK per encrypt) — decrypt-and-
    // compare is the only valid round-trip assertion shape, never a byte
    // comparison.
    {
        pg::PgConn conn{PQconnectdb(store.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult res = pg::exec_params(
            conn.get(),
            "SELECT encode(auth_credential,'hex') FROM offload_target_store.offload_targets "
            "WHERE id = 1",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(res.get()) == 1);
        std::string hex = PQgetvalue(res.get(), 0, 0);
        std::vector<std::uint8_t> blob;
        blob.reserve(hex.size() / 2);
        for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
            blob.push_back(static_cast<std::uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
        auto pk = pg::SecretCodec::encode_bigint_pk(1);
        auto dec = store.codec().decrypt(
            pg::SecretCodec::SecretId{"offload_target_store", "offload_targets",
                                      "auth_credential", pk},
            blob);
        REQUIRE(dec.has_value());
        std::string plaintext(reinterpret_cast<const char*>(dec->data()), dec->size());
        CHECK(plaintext == "legacy-plaintext-secret");
    }

    auto deliveries = store->get_deliveries(1);
    REQUIRE(deliveries.size() == 1);
    CHECK(deliveries[0].event_type == "execution.completed");
    CHECK(deliveries[0].status_code == 200);

    // Legacy file moved aside, never deleted.
    CHECK_FALSE(std::filesystem::exists(legacy_path));
    bool found_migrated = false;
    for (const auto& entry : std::filesystem::directory_iterator(legacy_path.parent_path())) {
        if (entry.path().string().find(legacy_path.filename().string() + ".migrated-") !=
            std::string::npos)
            found_migrated = true;
    }
    CHECK(found_migrated);

    // Re-running against the (now moved-aside) path is a no-op — the
    // fingerprint marker or the file's absence both make this trivially
    // idempotent.
    CHECK(store->migrate_from_sqlite(legacy_path));

    // Sequence fixup: a live create_target() after backfill must not
    // collide with the backfilled ids.
    auto live = store->create_target("live-after-backfill", "https://live.example.com/h",
                                     OffloadAuthType::None, "", "*");
    REQUIRE(live.has_value());
    CHECK(*live > 2);
}

TEST_CASE("OffloadTargetStore[pg]: migrate_from_sqlite refuses (fail-closed) on an orphaned "
          "delivery row",
          "[offload_store][pg][backfill]") {
    OffloadTargetStorePg store;
    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_offload_backfill_orphan_");

    LegacyOffloadFixtureDelivery orphan;
    orphan.id = 1;
    orphan.target_id = 999; // no such target in this legacy file
    orphan.event_type = "execution.completed";
    orphan.payload = "{}";
    orphan.delivered_at = 1700000000;

    write_legacy_offload_db(legacy_path, {}, {orphan});
    CHECK_FALSE(store->migrate_from_sqlite(legacy_path));

    // Nothing was committed — the whole backfill rolled back.
    auto targets = store->list();
    REQUIRE(targets.has_value());
    CHECK(targets->empty());
}

TEST_CASE("OffloadTargetStore[pg]: backfill credential-state conflict keeps the Postgres "
          "value (rotated-secret PG-wins rule)",
          "[offload_store][pg][backfill]") {
    OffloadTargetStorePg store;

    // Live-create a target — gets Postgres id 1 on this fresh schema.
    auto live = store->create_target("conflict-target", "https://conflict.example.com/h",
                                     OffloadAuthType::None, /*auth_credential=*/"",
                                     "execution.completed", /*batch_size=*/1, /*enabled=*/true);
    REQUIRE(live.has_value());
    REQUIRE(*live == 1);

    // A legacy row with the SAME id and matching identity fields, but a
    // credential the live row never had — the legacy content diverged from
    // Postgres only in credential state (e.g. the operator set a credential
    // after the legacy snapshot was taken, or rotated it away before this
    // backfill ever ran).
    auto by_id = store->get(1);
    REQUIRE(by_id.has_value());

    LegacyOffloadFixtureTarget conflicting;
    conflicting.id = 1;
    conflicting.name = "conflict-target";
    conflicting.url = "https://conflict.example.com/h";
    conflicting.auth_type = "none";
    conflicting.credential = "should-never-land-in-postgres";
    conflicting.event_types = "execution.completed";
    conflicting.batch_size = 1;
    conflicting.enabled = true;
    conflicting.created_at = by_id->created_at;

    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_offload_backfill_rotate_");
    write_legacy_offload_db(legacy_path, {conflicting}, {});

    // The mismatch is a logged warning, not a failure — identity otherwise
    // matches.
    REQUIRE(store->migrate_from_sqlite(legacy_path));

    auto after = store->get(1);
    REQUIRE(after.has_value());
    // Postgres's has_credential=false wins — backfill never reconciles
    // credential state onto an existing row.
    CHECK_FALSE(after->has_credential);
}
