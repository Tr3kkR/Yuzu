// test_plugin_config_store_pg.cpp — PluginConfigStore behaviour tests
// (PR1.5b). Born-on-Postgres, schema `plugin_config_store`. PG-gated: skips
// when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but broken
// (docs/postgres-store-playbook.md §7 skip-vs-fail contract).
//
// Construction order mirrors AuthDB's production wiring exactly (ADR-0010
// register-before-init, per-store SecretCodec instance): construct
// FileKeyProvider -> construct SecretCodec (ctor only) -> construct
// PluginConfigStore (registers its secret column) -> secret_codec.init().

#include <catch2/catch_test_macros.hpp>

#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "plugin_config_parsers.hpp"
#include "plugin_config_store.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>

using yuzu::server::FileKeyProvider;
using yuzu::server::PluginConfigStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::SecretCodec;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): pre-applies
// BOTH the `plugin_config_store` schema migration and the `secrets` schema
// migration (via a throwaway codec init), then resets `secrets.kek_meta` to
// the empty first-boot state — each test still mints its own KEK against its
// own fresh keys TempDir, exactly as on a plain empty database. Mirrors
// test_secret_codec.cpp's `secrets_tpl` pattern exactly; no key material
// reaches the shared template (the throwaway KEK's TempDir is destroyed at
// scope exit and kek_meta is emptied before the template is ever cloned).
yuzu::test::PgTestTemplate plugincfg_tpl{"plugincfg", [](const std::string& dsn) {
    yuzu::test::TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PluginConfigStore store{pool, codec};
    if (!store.is_open())
        throw std::runtime_error("plugincfg template: store failed to migrate");
    PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("plugincfg template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("plugincfg template: codec init failed to migrate");
    PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("plugincfg template: kek_meta reset failed");
}};

/// Fully-wired store for a test case: fresh keys dir, fresh codec, fresh
/// pool, `codec.init()` run in the correct order. Callers keep this alive
/// for the whole test case (it owns the pool and provider the store borrows).
struct Wired {
    yuzu::test::TempDir keys;
    FileKeyProvider provider{keys.path};
    SecretCodec codec{provider};
    PgPool pool;
    PluginConfigStore store;

    explicit Wired(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, store{pool, codec} {
        REQUIRE(store.is_open());
        PgConn conn{PQconnectdb(dsn.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto r = codec.init(conn.get());
        INFO((r ? std::string{} : r.error().message));
        REQUIRE(r.has_value());
    }
};

// Swaps a capturing sink onto the default logger for one test and restores
// it in the destructor (including on a throwing REQUIRE) — mirrors
// test_audit_store.cpp's `LogCapture`. Catch2 runs cases serially in one
// process, so no other test logs concurrently.
class LogCapture {
public:
    LogCapture() : saved_(spdlog::default_logger()) {
        sink_ = std::make_shared<spdlog::sinks::ostream_sink_mt>(stream_);
        auto logger = std::make_shared<spdlog::logger>("plugin_config_capture", sink_);
        logger->set_level(spdlog::level::trace);
        logger->set_pattern("%v");
        spdlog::set_default_logger(logger);
    }
    ~LogCapture() { spdlog::set_default_logger(saved_); }

    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    [[nodiscard]] bool says(std::string_view needle) const {
        return stream_.str().find(needle) != std::string::npos;
    }

private:
    std::ostringstream stream_;
    std::shared_ptr<spdlog::sinks::ostream_sink_mt> sink_;
    std::shared_ptr<spdlog::logger> saved_;
};

} // namespace

// ── Migration / fresh-database (plain YUZU_REQUIRE_PG_DB per the playbook's
//    §7 rule — this exercises migration itself, so it must NOT use the
//    pre-migrated template) ───────────────────────────────────────────────

TEST_CASE("PluginConfigStore opens on a fresh Postgres and migrates once",
          "[pg][store][plugin_config]") {
    YUZU_REQUIRE_PG_DB(db);
    Wired w{db.dsn()};
    CHECK(w.store.is_open());

    // Re-opening a second store against the SAME already-migrated database
    // is idempotent (the migration runner records the applied version and
    // does not re-run DDL) — a second store/codec pair opens cleanly too.
    yuzu::test::TempDir keys2;
    FileKeyProvider provider2(keys2.path);
    SecretCodec codec2(provider2);
    PluginConfigStore store2{w.pool, codec2};
    CHECK(store2.is_open());
}

// ── Store-behaviour tests: pre-migrated template (§7) ───────────────────

TEST_CASE("Config CRUD round-trips through set/get/list/delete", "[pg][store][plugin_config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    auto set1 = w.store.set_config("email", "smtp.host", "mail.example.com", "alice");
    REQUIRE(set1.has_value());
    CHECK(set1->plugin == "email");
    CHECK(set1->key == "smtp.host");
    CHECK(set1->value == "mail.example.com");
    CHECK(set1->updated_by == "alice");

    auto get1 = w.store.get_config("email", "smtp.host");
    REQUIRE(get1.has_value());
    CHECK(get1->value == "mail.example.com");

    // Overwrite — same (plugin, key), new value, RETURNING reflects it.
    auto set2 = w.store.set_config("email", "smtp.host", "mail2.example.com", "bob");
    REQUIRE(set2.has_value());
    CHECK(set2->value == "mail2.example.com");
    CHECK(set2->updated_by == "bob");

    w.store.set_config("email", "smtp.port", "587", "alice");
    w.store.set_config("firewall", "mode", "strict", "alice");

    auto listed_email = w.store.list_config("email");
    REQUIRE(listed_email.has_value());
    CHECK(listed_email->size() == 2);

    auto listed_all = w.store.list_config("");
    REQUIRE(listed_all.has_value());
    CHECK(listed_all->size() == 3);

    auto del = w.store.delete_config("email", "smtp.port");
    CHECK(del.has_value());
    auto after = w.store.get_config("email", "smtp.port");
    REQUIRE_FALSE(after.has_value());
    CHECK(after.error() == PluginConfigStore::Error::NotFound);

    // Deleting an already-absent key is NotFound, not a write failure.
    auto redel = w.store.delete_config("email", "smtp.port");
    REQUIRE_FALSE(redel.has_value());
    CHECK(redel.error() == PluginConfigStore::Error::NotFound);
}

TEST_CASE("get_config on a missing key is a typed NotFound, not an empty value",
          "[pg][store][plugin_config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    auto missing = w.store.get_config("nosuch", "key");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == PluginConfigStore::Error::NotFound);
}

TEST_CASE("set_config rejects an invalid plugin/key/value as InvalidInput",
          "[pg][store][plugin_config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    auto bad_plugin = w.store.set_config("Email", "host", "x", "alice");
    REQUIRE_FALSE(bad_plugin.has_value());
    CHECK(bad_plugin.error() == PluginConfigStore::Error::InvalidInput);

    const std::string oversized(9000, 'x');
    auto bad_value = w.store.set_config("email", "host", oversized, "alice");
    REQUIRE_FALSE(bad_value.has_value());
    CHECK(bad_value.error() == PluginConfigStore::Error::InvalidInput);
}

// ── Secret write-only contract ───────────────────────────────────────────

TEST_CASE("A secret's plaintext never appears in the returned struct or the stored row bytes",
          "[pg][store][plugin_config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    const std::string plaintext = "sk_live_super_secret_do_not_leak_12345";
    auto set = w.store.set_secret("email", "smtp.password", plaintext, "alice");
    REQUIRE(set.has_value());

    // SecretMeta has no value field at all — this is a structural guarantee,
    // not a runtime check, but pin the fields it DOES carry are the metadata
    // ones and nothing that looks like the plaintext leaked into them.
    CHECK(set->plugin == "email");
    CHECK(set->key == "smtp.password");
    CHECK(set->updated_by == "alice");
    CHECK(set->plugin.find(plaintext) == std::string::npos);
    CHECK(set->key.find(plaintext) == std::string::npos);
    CHECK(set->updated_by.find(plaintext) == std::string::npos);

    // The stored bytes are genuinely sealed — not the plaintext, not a
    // trivial encoding of it (e.g. base64), fetched straight off the wire in
    // binary format so no textual escaping could hide a substring match.
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult res{PQexecParams(conn.get(),
                              "SELECT sealed_value FROM plugin_config_store.secrets "
                              "WHERE plugin = 'email' AND key = 'smtp.password'",
                              0, nullptr, nullptr, nullptr, nullptr, /*resultFormat=*/1)};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    const auto* raw = reinterpret_cast<const std::uint8_t*>(PQgetvalue(res.get(), 0, 0));
    const int len = PQgetlength(res.get(), 0, 0);
    const std::string stored(reinterpret_cast<const char*>(raw), static_cast<std::size_t>(len));
    CHECK(stored.find(plaintext) == std::string::npos);
    CHECK(stored != plaintext);
    CHECK_FALSE(stored.empty()); // not the DEFAULT ''::bytea placeholder either
}

TEST_CASE("A secret's plaintext never appears in a log line emitted around set_secret",
          "[pg][store][plugin_config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    const std::string sentinel = "LOG-LEAK-SENTINEL-do-not-print-me-98765";
    LogCapture log;
    auto set = w.store.set_secret("email", "smtp.password", sentinel, "alice");
    REQUIRE(set.has_value());
    CHECK_FALSE(log.says(sentinel));
}

TEST_CASE("delete_secret removes the row; a second delete is NotFound",
          "[pg][store][plugin_config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set_secret("email", "api_key", "sk_abc123", "alice").has_value());
    auto del = w.store.delete_secret("email", "api_key");
    CHECK(del.has_value());
    auto redel = w.store.delete_secret("email", "api_key");
    REQUIRE_FALSE(redel.has_value());
    CHECK(redel.error() == PluginConfigStore::Error::NotFound);
}

TEST_CASE("A set secret decrypts under the deterministic scope_key AAD — the row genuinely "
          "round-trips, both fresh and on overwrite",
          "[pg][store][plugin_config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    auto decrypt_stored = [&](const std::string& plugin, const std::string& key) {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult res{PQexecParams(conn.get(),
                                  "SELECT sealed_value FROM plugin_config_store.secrets "
                                  "WHERE plugin = $1 AND key = $2",
                                  2,
                                  nullptr,
                                  std::array<const char*, 2>{plugin.c_str(), key.c_str()}.data(),
                                  nullptr, nullptr, /*resultFormat=*/1)};
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(res.get()) == 1);
        const auto* raw = reinterpret_cast<const std::uint8_t*>(PQgetvalue(res.get(), 0, 0));
        const auto len = static_cast<std::size_t>(PQgetlength(res.get(), 0, 0));
        auto pk = yuzu::server::plugin_config::parse_plugin_key(plugin, key);
        REQUIRE(pk.has_value());
        const std::string scope_key = yuzu::server::plugin_config::canonical_plugin_key(*pk);
        auto dec = w.codec.decrypt(
            SecretCodec::SecretId{"plugin_config_store", "secrets", "sealed_value", scope_key},
            std::span<const std::uint8_t>{raw, len});
        REQUIRE(dec.has_value());
        return std::string(reinterpret_cast<const char*>(dec->data()), dec->size());
    };

    REQUIRE(w.store.set_secret("email", "smtp.password", "first-value", "alice").has_value());
    CHECK(decrypt_stored("email", "smtp.password") == "first-value");

    // Overwrite: a fresh DEK, same scope_key AAD, still decrypts.
    REQUIRE(w.store.set_secret("email", "smtp.password", "second-value", "bob").has_value());
    CHECK(decrypt_stored("email", "smtp.password") == "second-value");
}

TEST_CASE("set_secret rejects an empty or oversized plaintext as InvalidInput",
          "[pg][store][plugin_config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    auto empty = w.store.set_secret("email", "api_key", "", "alice");
    REQUIRE_FALSE(empty.has_value());
    CHECK(empty.error() == PluginConfigStore::Error::InvalidInput);

    const std::string oversized(70 * 1024, 'x');
    auto huge = w.store.set_secret("email", "api_key", oversized, "alice");
    REQUIRE_FALSE(huge.has_value());
    CHECK(huge.error() == PluginConfigStore::Error::InvalidInput);
}

// ── Kill switch ───────────────────────────────────────────────────────────

TEST_CASE("Kill switch: no row at either level defaults to allowed",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    CHECK(w.store.action_allowed("firewall", "block"));
    CHECK(w.store.action_allowed("firewall", ""));

    auto entry = w.store.get_kill_switch("firewall", "block");
    REQUIRE(entry.has_value());
    CHECK(entry->enabled);
    CHECK(entry->reason.empty());
}

TEST_CASE("Kill switch: a plugin-level flip disables every action under it",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    auto set = w.store.set_kill_switch("firewall", "", false, "incident 42", "alice");
    REQUIRE(set.has_value());
    CHECK_FALSE(set->enabled);

    CHECK_FALSE(w.store.action_allowed("firewall", "block"));
    CHECK_FALSE(w.store.action_allowed("firewall", "allow"));
    CHECK_FALSE(w.store.action_allowed("firewall", ""));
    // A different plugin is unaffected.
    CHECK(w.store.action_allowed("email", "send"));
}

TEST_CASE("Kill switch: an action-level row overrides an inherited plugin-level state",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set_kill_switch("firewall", "", false, "lockdown", "alice").has_value());
    // Re-enable just one action under the plugin-level kill.
    REQUIRE(w.store.set_kill_switch("firewall", "audit", true, "audit still needed", "alice")
                .has_value());

    CHECK_FALSE(w.store.action_allowed("firewall", "block")); // still inherits plugin-level
    CHECK(w.store.action_allowed("firewall", "audit"));       // action-level override wins

    auto entry = w.store.get_kill_switch("firewall", "audit");
    REQUIRE(entry.has_value());
    CHECK(entry->enabled);
    CHECK(entry->action == "audit");
}

TEST_CASE("set_kill_switch rejects an invalid reason as InvalidInput",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    const std::string bad_reason = "bad\r\nheader-injection";
    auto res = w.store.set_kill_switch("firewall", "", false, bad_reason, "alice");
    REQUIRE_FALSE(res.has_value());
    CHECK(res.error() == PluginConfigStore::Error::InvalidInput);
}

// ── Fail-closed evaluation on a degraded store (no live Postgres needed —
//    a bad conninfo fails fast and deterministically) ────────────────────

TEST_CASE("A degraded/unopened store makes action_allowed return false, never true",
          "[server][config][killswitch]") {
    PgPool bad_pool{{.conninfo = "host=127.0.0.1 port=1 dbname=nonexistent",
                     .size = 1,
                     .connect_timeout_s = 1}};
    yuzu::test::TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PluginConfigStore store{bad_pool, codec};
    REQUIRE_FALSE(store.is_open());

    // Fail-closed: unopened means every action reads as disabled, never
    // "allowed" — the whole point of action_allowed's collapse (ADR-0036).
    CHECK_FALSE(store.action_allowed("firewall", "block"));
    CHECK_FALSE(store.action_allowed("email", ""));

    // The display accessor surfaces the degradation as a typed error rather
    // than silently answering "enabled" — a caller that (incorrectly) tried
    // to use it for a go/no-go decision would at least see an error to
    // mishandle, not a confident wrong answer.
    auto entry = store.get_kill_switch("firewall", "block");
    REQUIRE_FALSE(entry.has_value());
    CHECK(entry.error() == PluginConfigStore::Error::Unavailable);
}
