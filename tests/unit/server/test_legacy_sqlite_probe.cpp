/**
 * test_legacy_sqlite_probe.cpp — Unit tests for the shared fresh-start
 * detect-and-warn helper (`legacy_sqlite_probe.hpp`), introduced with
 * ADR-0061 (UpdateRegistry) and reused by the sibling PatchManager/
 * DirectorySync migrations. Pure SQLite + filesystem — no Postgres needed.
 */

#include "legacy_sqlite_probe.hpp"

#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using yuzu::server::SqliteDb;
using yuzu::server::SqliteErrMsg;
using yuzu::server::legacy_sqlite_probe::warn_if_legacy_rows;

TEST_CASE("legacy_sqlite_probe: silent when the legacy file does not exist",
          "[legacy_sqlite_probe]") {
    auto path = yuzu::test::unique_temp_path("yuzu_test_legacyprobe_nofile_");
    REQUIRE_FALSE(std::filesystem::exists(path));

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(path, "TestStore", {"widgets"});
    cap.stop();
    CHECK(cap.text().find("legacy") == std::string::npos);
}

TEST_CASE("legacy_sqlite_probe: silent when the probed table is absent",
          "[legacy_sqlite_probe]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_legacyprobe_notable_"};
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(), "CREATE TABLE unrelated (x INTEGER);", nullptr, nullptr,
                             err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy.path, "TestStore", {"widgets"});
    cap.stop();
    CHECK(cap.text().find("legacy") == std::string::npos);
}

TEST_CASE("legacy_sqlite_probe: silent when the probed table is empty",
          "[legacy_sqlite_probe]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_legacyprobe_empty_"};
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(), "CREATE TABLE widgets (id INTEGER PRIMARY KEY);", nullptr,
                             nullptr, err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy.path, "TestStore", {"widgets"});
    cap.stop();
    CHECK(cap.text().find("legacy") == std::string::npos);
}

TEST_CASE("legacy_sqlite_probe: warns with a row count when real rows exist",
          "[legacy_sqlite_probe]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_legacyprobe_realdata_"};
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(),
                             "CREATE TABLE widgets (id INTEGER PRIMARY KEY); "
                             "INSERT INTO widgets VALUES (1),(2),(3);",
                             nullptr, nullptr, err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy.path, "TestStore", {"widgets"});
    cap.stop();
    const std::string text = cap.text();
    CHECK(text.find("TestStore") != std::string::npos);
    CHECK(text.find("widgets") != std::string::npos);
    CHECK(text.find("holds 3 row(s)") != std::string::npos);
    CHECK(text.find(legacy.path.string()) != std::string::npos);
}

TEST_CASE("legacy_sqlite_probe: multi-table store warns once per non-empty table, stays "
          "silent for empty/absent ones",
          "[legacy_sqlite_probe]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_legacyprobe_multi_"};
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(),
                             "CREATE TABLE a (id INTEGER PRIMARY KEY); "
                             "CREATE TABLE b (id INTEGER PRIMARY KEY); "
                             "INSERT INTO a VALUES (1);", // b stays empty; c is never created
                             nullptr, nullptr, err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy.path, "TestStore", {"a", "b", "c"});
    cap.stop();
    const std::string text = cap.text();
    CHECK(text.find("table 'a'") != std::string::npos);
    CHECK(text.find("holds 1 row(s)") != std::string::npos);
    CHECK(text.find("table 'b'") == std::string::npos);
    CHECK(text.find("table 'c'") == std::string::npos);
}

TEST_CASE("legacy_sqlite_probe: warns defensively when the legacy file is corrupt",
          "[legacy_sqlite_probe]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_legacyprobe_corrupt_"};
    {
        std::ofstream f(legacy.path, std::ios::binary);
        REQUIRE(f.is_open());
        f << "this is not a valid sqlite database file";
    }

    yuzu::test::LogCapture cap;
    warn_if_legacy_rows(legacy.path, "TestStore", {"widgets"});
    cap.stop();
    CHECK(cap.text().find("legacy") != std::string::npos);
}
