// PgTestTemplate lifecycle wiring + its tests.
//
// Listener (one dedicated TU — CATCH_REGISTER_LISTENER in a header would
// register one listener per including TU):
//  - testRunStarting: sweep stale yuzu_test_* databases leaked by ABNORMAL
//    exits of earlier runs (SIGKILL / OOM / CI job-timeout kill — nothing
//    re-runs those processes' teardown). Age comes from the epoch embedded
//    in every test-database name; the threshold is far beyond any CI job's
//    lifetime, so a live concurrent suite on the shared instance can never
//    be swept.
//  - testRunEnded: drop this process's template databases while libpq's TLS
//    stack is still alive. The Registry static dtor is only a backstop: its
//    __cxa_atexit slot is claimed when the first [pg] fixture runs, so on
//    Catch2-filtered runs OpenSSL's own atexit cleanup can land AFTER it
//    and the exit-time PQconnectdb fails (see PgTestTemplate::drop_all_built
//    in test_helpers.hpp).
//
// The TEST_CASEs below are the regression net the 2091 review asked for: a
// change that no-ops drop_all_built(), breaks the shared-key replay
// verification, or mis-ages database names now fails the suite itself
// rather than only an external leftover-database check.

#if defined(YUZU_TEST_ENABLE_PG)

#include <catch2/catch_test_macros.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <stdexcept>
#include <string>

namespace {

class PgTemplateCleanupListener : public Catch::EventListenerBase {
public:
    using Catch::EventListenerBase::EventListenerBase;

    void testRunStarting(Catch::TestRunInfo const& /*info*/) override {
        const char* dsn = yuzu::test::pg_admin_dsn_env();
        if (dsn != nullptr)
            yuzu::test::sweep_stale_test_databases(dsn);
    }

    void testRunEnded(Catch::TestRunStats const& /*stats*/) override {
        yuzu::test::PgTestTemplate::drop_all_built();
    }
};

// Probe setups for the replay-verification test. Three distinct functions
// (distinct pointers — the same shape as byte-identical lambdas in
// different TUs): two structurally equivalent, one divergent.
void probe_exec(const std::string& dsn, const char* sql) {
    yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error(std::string("probe connect failed: ") +
                                 PQerrorMessage(conn.get()));
    yuzu::server::pg::PgResult res{PQexec(conn.get(), sql)};
    if (!res.ok())
        throw std::runtime_error(std::string("probe sql failed: ") + PQerrorMessage(conn.get()));
}

constexpr const char* kProbeSchema =
    "CREATE SCHEMA IF NOT EXISTS tplprobe;"
    "CREATE TABLE IF NOT EXISTS tplprobe.t1 (id INTEGER)";

void probe_setup(const std::string& dsn) { probe_exec(dsn, kProbeSchema); }
void probe_setup_twin(const std::string& dsn) { probe_exec(dsn, kProbeSchema); }
void probe_setup_divergent(const std::string& dsn) {
    probe_exec(dsn, kProbeSchema);
    probe_exec(dsn, "CREATE TABLE IF NOT EXISTS tplprobe.t2 (id INTEGER)");
}

bool database_exists(const std::string& admin_dsn, const std::string& db_name) {
    yuzu::server::pg::PgConn conn{PQconnectdb(admin_dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    const char* values[] = {db_name.c_str()};
    yuzu::server::pg::PgResult res{PQexecParams(
        conn.get(), "SELECT 1 FROM pg_database WHERE datname = $1", 1, nullptr, values, nullptr,
        nullptr, 0)};
    REQUIRE(PQresultStatus(res.get()) == PGRES_TUPLES_OK);
    return PQntuples(res.get()) == 1;
}

} // namespace

CATCH_REGISTER_LISTENER(PgTemplateCleanupListener)

TEST_CASE("test_db_is_stale: name-embedded epoch + staleness window", "[template]") {
    const std::int64_t now = 1'783'900'000; // fixed "now" — the predicate is pure
    const std::string old_epoch = std::to_string(now - 7 * 3600);
    const std::string fresh_epoch = std::to_string(now - 60);

    SECTION("stale ephemeral and template names sweep") {
        CHECK(yuzu::test::test_db_is_stale("yuzu_test_" + old_epoch + "_123456789_0", now));
        CHECK(yuzu::test::test_db_is_stale("yuzu_test_tpl_" + old_epoch + "_123456789_swinv", now));
    }
    SECTION("fresh names never sweep") {
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_" + fresh_epoch + "_123456789_0", now));
        CHECK_FALSE(
            yuzu::test::test_db_is_stale("yuzu_test_tpl_" + fresh_epoch + "_1_swinv", now));
    }
    SECTION("pre-epoch-format names never sweep (rollout safety: a concurrent "
            "old-binary job may own them)") {
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_987654321_0", now));
    }
    SECTION("implausible epochs and malformed names never sweep") {
        const std::string future = std::to_string(now + 7 * 86'400);
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_" + future + "_1_0", now));
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_notanumber_0", now));
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_", now));
        CHECK_FALSE(yuzu::test::test_db_is_stale("other_db", now));
        // charset guard: never splice a quotable name into DROP
        CHECK_FALSE(yuzu::test::test_db_is_stale("yuzu_test_" + old_epoch + "_1_a\"b", now));
    }
}

TEST_CASE("PgTestTemplate: build, shared-key replay verification, drop_all_built",
          "[pg][template]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    }
    const std::string admin = yuzu::test::pg_admin_dsn_env();

    yuzu::test::PgTestTemplate original{"tplprobe", &probe_setup};
    yuzu::test::PgTestTemplate twin{"tplprobe", &probe_setup_twin};
    yuzu::test::PgTestTemplate divergent{"tplprobe", &probe_setup_divergent};

    std::string err;
    const std::string built = original.ensure(admin, err);
    INFO("build error: " << err);
    REQUIRE(err.empty());
    REQUIRE_FALSE(built.empty());
    CHECK(database_exists(admin, built));

    SECTION("a structurally equivalent setup under the same key verifies and shares") {
        std::string twin_err;
        CHECK(twin.ensure(admin, twin_err) == built);
        CHECK(twin_err.empty());
    }

    SECTION("a divergent setup under the same key is rejected; the original is untouched") {
        std::string div_err;
        CHECK(divergent.ensure(admin, div_err).empty());
        CHECK(div_err.find("shared-key setup mismatch") != std::string::npos);

        std::string again_err;
        CHECK(original.ensure(admin, again_err) == built);
        CHECK(again_err.empty());
    }

    SECTION("drop_all_built removes the template (the testRunEnded contract)") {
        yuzu::test::PgTestTemplate::drop_all_built();
        CHECK_FALSE(database_exists(admin, built));
        // Later ensures rebuild transparently — the registry entry is gone.
        // (The rebuilt name embeds a fresh creation epoch, so it is not
        // asserted equal to the old one.)
        std::string rebuilt_err;
        const std::string rebuilt = original.ensure(admin, rebuilt_err);
        CHECK(rebuilt_err.empty());
        REQUIRE_FALSE(rebuilt.empty());
        CHECK(database_exists(admin, rebuilt));
    }
}

#endif // YUZU_TEST_ENABLE_PG
