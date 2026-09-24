/// HA WS-8: the multi-host DSN guard (pg/multi_host_dsn.hpp). A multi-host DSN
/// without target_session_attrs lets libpq put the pool's connections on a
/// standby; the guard appends read-write, and refuses a weaker explicit value.

#include "pg/multi_host_dsn.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <optional>
#include <string>

using yuzu::server::pg::enforce_multi_host_read_write;

TEST_CASE("multi-host DSN guard: a single host is left alone", "[server][pg][multi_host_dsn]") {
    for (const std::string dsn :
         {"host=db port=5432 dbname=yuzu user=yuzu", "postgresql://yuzu:pw@db:5432/yuzu",
          "host=db target_session_attrs=any"}) {
        INFO(dsn);
        const auto r = enforce_multi_host_read_write(dsn);
        REQUIRE(r.has_value());
        CHECK(r->dsn == dsn);
        CHECK_FALSE(r->appended);
        CHECK(r->hosts == 1);
    }
}

TEST_CASE("multi-host DSN guard: no target_session_attrs gets read-write appended",
          "[server][pg][multi_host_dsn]") {
    SECTION("keyword form") {
        const auto r = enforce_multi_host_read_write("host=a,b,c dbname=yuzu");
        REQUIRE(r.has_value());
        CHECK(r->appended);
        CHECK(r->hosts == 3);
        CHECK(r->dsn == "host=a,b,c dbname=yuzu target_session_attrs=read-write");
    }
    SECTION("URI form, with and without an existing query string") {
        const auto a = enforce_multi_host_read_write("postgresql://u:p@a:5432,b:5432/yuzu");
        REQUIRE(a.has_value());
        CHECK(a->dsn == "postgresql://u:p@a:5432,b:5432/yuzu?target_session_attrs=read-write");
        const auto b = enforce_multi_host_read_write("postgresql://u:p@a,b/yuzu?sslmode=require");
        REQUIRE(b.has_value());
        CHECK(b->dsn ==
              "postgresql://u:p@a,b/yuzu?sslmode=require&target_session_attrs=read-write");
    }
    SECTION("a hostaddr list counts as multi-host") {
        const auto r = enforce_multi_host_read_write("hostaddr=10.0.0.1,10.0.0.2 dbname=yuzu");
        REQUIRE(r.has_value());
        CHECK(r->appended);
        CHECK(r->hosts == 2);
    }
    SECTION("load_balance_hosts turns the guard on even for the attribute's absence") {
        const auto r = enforce_multi_host_read_write("host=a,b load_balance_hosts=random");
        REQUIRE(r.has_value());
        CHECK(r->appended);
        const auto off = enforce_multi_host_read_write("host=a load_balance_hosts=disable");
        REQUIRE(off.has_value());
        CHECK_FALSE(off->appended);
    }
}

TEST_CASE("multi-host DSN guard: read-write and primary are accepted as given",
          "[server][pg][multi_host_dsn]") {
    for (const std::string dsn :
         {"host=a,b target_session_attrs=read-write", "host=a,b target_session_attrs=primary",
          "host=a,b load_balance_hosts=random target_session_attrs=read-write"}) {
        INFO(dsn);
        const auto r = enforce_multi_host_read_write(dsn);
        REQUIRE(r.has_value());
        CHECK(r->dsn == dsn);
        CHECK_FALSE(r->appended);
    }
}

TEST_CASE("multi-host DSN guard: a weaker explicit target_session_attrs is refused, without "
          "echoing the DSN",
          "[server][pg][multi_host_dsn]") {
    for (const std::string tsa : {"any", "read-only", "standby", "prefer-standby"}) {
        INFO(tsa);
        const auto r =
            enforce_multi_host_read_write("host=a,b password=s3cret target_session_attrs=" + tsa);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("'" + tsa + "'") != std::string::npos);
        CHECK(r.error().find("s3cret") == std::string::npos);
    }
}

TEST_CASE("multi-host DSN guard: an unparseable DSN is returned unchanged for the pool to report",
          "[server][pg][multi_host_dsn]") {
    const auto r = enforce_multi_host_read_write("host=a,b sslmode=");
    // Whatever libpq makes of it, the guard must not throw or invent a DSN.
    REQUIRE(r.has_value());
    const auto bad = enforce_multi_host_read_write("postgresql://u:s3cr%zzt@a,b/yuzu");
    REQUIRE(bad.has_value());
    CHECK(bad->dsn == "postgresql://u:s3cr%zzt@a,b/yuzu");
    CHECK_FALSE(bad->appended);
}

#ifndef _WIN32
TEST_CASE("multi-host DSN guard: a host list from PGHOST counts", "[server][pg][multi_host_dsn]") {
    // Process environment is shared by the whole test binary: restore it.
    const char* prev = std::getenv("PGHOST");
    const std::optional<std::string> saved = prev ? std::optional<std::string>(prev) : std::nullopt;
    ::setenv("PGHOST", "a,b", 1);
    const auto r = enforce_multi_host_read_write("dbname=yuzu user=yuzu");
    if (saved)
        ::setenv("PGHOST", saved->c_str(), 1);
    else
        ::unsetenv("PGHOST");
    REQUIRE(r.has_value());
    CHECK(r->appended);
    CHECK(r->hosts == 2);
}
#endif
