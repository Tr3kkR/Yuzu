/**
 * test_asset_tags_store.cpp -- asset_tags_store.hpp (#232): the atomic
 * state-file lifecycle. Filesystem-backed (one small file per case in a
 * TempDir) because the defect class -- non-atomic write, and on Windows an
 * open handle during rename -- is unobservable from pure code. No threads,
 * clocks, sleeps or processes.
 *
 * Atomicity is asserted, not assumed (code-review F-codex-3): on POSIX the
 * replace case holds a descriptor on the OLD file across the write and
 * proves the destination changed inode while the old descriptor still reads
 * the whole old content -- a direct truncate+write over the destination
 * fails both checks deterministically, with no timing involved.
 */
#include "asset_tags_parsers.hpp"
#include "asset_tags_store.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace yuzu::asset_tags;
namespace fs = std::filesystem;

namespace {

fs::path tmp_of(const fs::path& dest) {
    fs::path t = dest;
    t += ".tmp";
    return t;
}

// A write that succeeded with no warning attached.
bool wrote_clean(const std::expected<std::optional<WriteWarning>, IoError>& r) {
    return r.has_value() && !r->has_value();
}

} // namespace

TEST_CASE("asset_tags store: first write creates the file", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "sub" / "asset_tags.json";

    REQUIRE(wrote_clean(write_state_file_atomic(dest, "{\"a\":1}")));
    CHECK(fs::exists(dest));
    CHECK_FALSE(fs::exists(tmp_of(dest)));

    auto text = read_state_file(dest);
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    CHECK(**text == "{\"a\":1}");

#ifndef _WIN32
    CHECK(fs::status(dest).permissions() ==
          (fs::perms::owner_read | fs::perms::owner_write));
#endif
}

TEST_CASE("asset_tags store: replace is atomic and leaves no temp", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "asset_tags.json";

    REQUIRE(wrote_clean(write_state_file_atomic(dest, "AAAA")));
    REQUIRE(wrote_clean(write_state_file_atomic(dest, "B")));
    auto text = read_state_file(dest);
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    CHECK(**text == "B");
    CHECK_FALSE(fs::exists(tmp_of(dest)));

#ifndef _WIN32
    // Hold the OLD file open across the replace. A rename swaps the directory
    // entry to a new inode and leaves the old one intact for its readers; a
    // truncate+write in place would keep the inode and overwrite what the
    // reader sees. Both checks are deterministic -- no reader races a writer.
    struct stat before {};
    REQUIRE(::stat(dest.c_str(), &before) == 0);
    const int old_fd = ::open(dest.c_str(), O_RDONLY);
    REQUIRE(old_fd >= 0);

    REQUIRE(wrote_clean(write_state_file_atomic(dest, "CCCCCCCC")));

    struct stat after {};
    REQUIRE(::stat(dest.c_str(), &after) == 0);
    CHECK(after.st_ino != before.st_ino);

    struct stat old_now {};
    REQUIRE(::fstat(old_fd, &old_now) == 0);
    CHECK(old_now.st_nlink == 0); // the old inode was unlinked by the rename, not rewritten

    std::string old_view;
    char buf[64];
    for (ssize_t n = ::read(old_fd, buf, sizeof buf); n > 0; n = ::read(old_fd, buf, sizeof buf))
        old_view.append(buf, static_cast<std::size_t>(n));
    ::close(old_fd);
    CHECK(old_view == "B"); // wholly old -- never "CCCCCCCC", never empty

    text = read_state_file(dest);
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    CHECK(**text == "CCCCCCCC"); // wholly new through the path
    CHECK_FALSE(fs::exists(tmp_of(dest)));
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

    REQUIRE(wrote_clean(write_state_file_atomic(dest, serialize_state(st))));
    auto text = read_state_file(dest);
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    auto parsed = parse_state(**text);
    REQUIRE(parsed.has_value());
    CHECK(parsed->tags == st.tags);
    CHECK(parsed->change_log.size() == st.change_log.size());

    SECTION("a corrupt file is read, rejected by the parser, then replaced") {
        REQUIRE(wrote_clean(write_state_file_atomic(dest, "{not json")));
        text = read_state_file(dest);
        REQUIRE(text.has_value());
        REQUIRE(text->has_value());
        auto rejected = parse_state(**text);
        REQUIRE_FALSE(rejected.has_value());
        CHECK_FALSE(rejected.error().message.empty());

        REQUIRE(wrote_clean(write_state_file_atomic(dest, serialize_state(st))));
        text = read_state_file(dest);
        REQUIRE(text.has_value());
        REQUIRE(text->has_value());
        CHECK(parse_state(**text).has_value());
    }
}

TEST_CASE("asset_tags store: failure paths", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    std::error_code mk_ec;
    fs::create_directories(dir.path, mk_ec); // TempDir only reserves the name
    REQUIRE_FALSE(mk_ec);

    SECTION("parent path is a regular file") {
        const auto blocker = dir.path / "blocker";
        {
            std::ofstream f(blocker, std::ios::binary);
            f << "x";
        }
        const auto dest = blocker / "asset_tags.json";
        auto r = write_state_file_atomic(dest, "{}");
        REQUIRE_FALSE(r.has_value());
        CHECK_FALSE(r.error().message.empty());
        CHECK_FALSE(fs::exists(tmp_of(dest)));
    }
    SECTION("a missing file is a first run, not an error") {
        auto text = read_state_file(dir.path / "absent.json");
        REQUIRE(text.has_value());
        CHECK_FALSE(text->has_value());
    }
    SECTION("a directory is an error") {
        auto text = read_state_file(dir.path);
        REQUIRE_FALSE(text.has_value());
        CHECK_FALSE(text.error().message.empty());
    }
}
