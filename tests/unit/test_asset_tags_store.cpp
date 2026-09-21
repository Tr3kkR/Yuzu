/**
 * test_asset_tags_store.cpp -- asset_tags_store.hpp (#232): the atomic
 * state-file lifecycle. Filesystem-backed (one small file per case in a
 * TempDir) because the defect class -- non-atomic write, and on Windows an
 * open handle during rename -- is unobservable from pure code. No threads,
 * clocks, sleeps or processes.
 */
#include "asset_tags_parsers.hpp"
#include "asset_tags_store.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

using namespace yuzu::asset_tags;
namespace fs = std::filesystem;

namespace {

fs::path tmp_of(const fs::path& dest) {
    fs::path t = dest;
    t += ".tmp";
    return t;
}

} // namespace

TEST_CASE("asset_tags store: first write creates the file", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "sub" / "asset_tags.json";

    std::string err;
    REQUIRE(write_state_file_atomic(dest, "{\"a\":1}", err));
    CHECK(err.empty());
    CHECK(fs::exists(dest));
    CHECK_FALSE(fs::exists(tmp_of(dest)));

    auto text = read_state_file(dest, err);
    REQUIRE(text.has_value());
    CHECK(*text == "{\"a\":1}");

#ifndef _WIN32
    CHECK(fs::status(dest).permissions() ==
          (fs::perms::owner_read | fs::perms::owner_write));
#endif
}

TEST_CASE("asset_tags store: replace leaves no temp", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "asset_tags.json";

    std::string err;
    REQUIRE(write_state_file_atomic(dest, "AAAA", err));
    REQUIRE(write_state_file_atomic(dest, "B", err));
    auto text = read_state_file(dest, err);
    REQUIRE(text.has_value());
    CHECK(*text == "B");
    CHECK_FALSE(fs::exists(tmp_of(dest)));

#ifndef _WIN32
    // A reader holding the old file open must not block the replace.
    std::ifstream reader(dest, std::ios::binary);
    REQUIRE(reader.is_open());
    REQUIRE(write_state_file_atomic(dest, "C", err));
    reader.close();
    text = read_state_file(dest, err);
    REQUIRE(text.has_value());
    CHECK(*text == "C");
#endif
}

TEST_CASE("asset_tags store: restart recovery", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "asset_tags.json";

    AssetTagState st;
    CategoryValues v{"db", "Production", "Rack A|3", ""};
    apply_sync(st, v, 100);
    v[0] = "db2";
    apply_sync(st, v, 200);
    REQUIRE(st.tags.size() == 3);
    REQUIRE(st.change_log.size() == 4);

    std::string err;
    REQUIRE(write_state_file_atomic(dest, serialize_state(st), err));
    auto text = read_state_file(dest, err);
    REQUIRE(text.has_value());
    auto parsed = parse_state(*text, err);
    REQUIRE(parsed.has_value());
    CHECK(parsed->tags == st.tags);
    CHECK(parsed->change_log.size() == st.change_log.size());

    SECTION("a corrupt file is read, rejected by the parser, then replaced") {
        REQUIRE(write_state_file_atomic(dest, "{not json", err));
        text = read_state_file(dest, err);
        REQUIRE(text.has_value());
        CHECK_FALSE(parse_state(*text, err).has_value());
        CHECK_FALSE(err.empty());

        REQUIRE(write_state_file_atomic(dest, serialize_state(st), err));
        text = read_state_file(dest, err);
        REQUIRE(text.has_value());
        CHECK(parse_state(*text, err).has_value());
    }
}

TEST_CASE("asset_tags store: failure paths", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    std::error_code mk_ec;
    fs::create_directories(dir.path, mk_ec); // TempDir only reserves the name
    REQUIRE_FALSE(mk_ec);
    std::string err;

    SECTION("parent path is a regular file") {
        const auto blocker = dir.path / "blocker";
        {
            std::ofstream f(blocker, std::ios::binary);
            f << "x";
        }
        const auto dest = blocker / "asset_tags.json";
        CHECK_FALSE(write_state_file_atomic(dest, "{}", err));
        CHECK_FALSE(err.empty());
        CHECK_FALSE(fs::exists(tmp_of(dest)));
    }
    SECTION("a missing file is a first run, not an error") {
        auto text = read_state_file(dir.path / "absent.json", err);
        CHECK_FALSE(text.has_value());
        CHECK(err.empty());
    }
    SECTION("a directory is an error") {
        auto text = read_state_file(dir.path, err);
        CHECK_FALSE(text.has_value());
        CHECK_FALSE(err.empty());
    }
}
