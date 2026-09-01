// Pure unit tests for confined_fs_walk.hpp's walk_delete, driven by a FAKE
// in-memory Ops. No filesystem, no OS headers -- this file includes only
// confined_fs_rules.hpp + confined_fs_walk.hpp.

#include <yuzu/agent/confined_fs_rules.hpp>
#include <yuzu/agent/confined_fs_walk.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::agent::confined_fs;

namespace {

// A fake in-memory directory tree. Directories are keyed by an opaque int
// id; each holds a list of DirEntry plus (for subdirectories) the child id
// to open. No real fd/HANDLE ever exists.
struct FakeDir {
    std::vector<DirEntry> entries;
    std::map<std::string, int> subdirs;      // name -> child dir id
    std::map<std::string, Reason> refusals;  // name -> open_dir policy refusal
    std::map<std::string, int> os_errors_open; // name -> os_error for OsError refusal
    bool enumerate_os_error = false;
    int enumerate_os_error_code = 0;
};

class FakeOps {
public:
    using DirHandle = int; // just the dir id; move-only isn't needed for an int

    explicit FakeOps(std::chrono::steady_clock::time_point start_time) : now_(start_time) {}

    int add_dir() {
        int id = next_id_++;
        dirs_[id] = FakeDir{};
        return id;
    }

    FakeDir& dir(int id) { return dirs_[id]; }

    void advance(std::chrono::milliseconds by) { now_ += by; }

    std::chrono::steady_clock::time_point now() { return now_; }

    OpenDirRes<DirHandle> open_dir(DirHandle& parent, const std::string& name) {
        FakeDir& p = dirs_.at(parent);
        if (auto it = p.refusals.find(name); it != p.refusals.end())
            return OpenDirRes<DirHandle>{std::nullopt, it->second, 0};
        if (auto it = p.os_errors_open.find(name); it != p.os_errors_open.end())
            return OpenDirRes<DirHandle>{std::nullopt, Reason::OsError, it->second};
        int child = p.subdirs.at(name);
        return OpenDirRes<DirHandle>{child, Reason::None, 0};
    }

    EnumerateResult enumerate(DirHandle& d, const EnumBudget& budget) {
        FakeDir& fd = dirs_.at(d);
        last_budget_ = budget;
        ++enumerate_calls_;
        if (fd.enumerate_os_error)
            return EnumerateResult{{}, Reason::OsError, fd.enumerate_os_error_code};
        if (now() >= budget.deadline)
            return EnumerateResult{{}, Reason::WallTimeCap, 0};
        std::vector<DirEntry> out;
        for (auto& e : fd.entries) {
            if (out.size() >= budget.max_entries)
                return EnumerateResult{out, Reason::EntryCap, 0};
            out.push_back(e);
        }
        Reason r = out.size() < fd.entries.size() ? Reason::EntryCap : Reason::None;
        return EnumerateResult{out, r, 0};
    }

    UnlinkOutcome unlink(DirHandle& parent, const std::string& name, UnlinkKind kind) {
        (void)kind;
        ++unlink_calls_;
        unlinked_names_.push_back(name);
        if (auto it = fail_unlink_.find(std::pair{parent, name}); it != fail_unlink_.end())
            return UnlinkOutcome{EntryStatus::Failed, Reason::OsError, it->second};
        return UnlinkOutcome{EntryStatus::Deleted, Reason::None, 0};
    }

    void fail_unlink_with(DirHandle parent, const std::string& name, int errnum) {
        fail_unlink_[{parent, name}] = errnum;
    }

    std::chrono::steady_clock::time_point now_;
    std::map<int, FakeDir> dirs_;
    int next_id_ = 0;
    int unlink_calls_ = 0;
    int enumerate_calls_ = 0;
    std::vector<std::string> unlinked_names_;
    std::map<std::pair<int, std::string>, int> fail_unlink_;
    EnumBudget last_budget_{};
};

DirEntry file_entry(std::string name, std::uint64_t size = 10) {
    return DirEntry{std::move(name), EntryMeta{EntryType::RegularFile, size, true}, 0, false};
}

DirEntry dir_entry(std::string name) {
    return DirEntry{std::move(name), EntryMeta{EntryType::Directory, 0, true}, 0, false};
}

constexpr DeleteLimits kOpenLimits{
    /*max_entries=*/1000,
    /*max_bytes=*/1'000'000,
    /*max_wall=*/std::chrono::milliseconds{60'000},
    /*max_depth=*/32,
};

MatchFn always_match = [](std::string_view) { return true; };
MatchFn never_match = [](std::string_view) { return false; };

} // namespace

TEST_CASE("walk_delete happy path deletes every matched regular file", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("b.txt")};

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.stop_reason == Reason::None);
    REQUIRE(result.entries.size() == 2);
    REQUIRE(result.entries[0].status == EntryStatus::Deleted);
    REQUIRE(result.entries[1].status == EntryStatus::Deleted);
    REQUIRE(result.tally.entries_seen == 2);
    REQUIRE(result.tally.bytes_deleted == 20);
    REQUIRE(ops.unlink_calls_ == 2);
}

TEST_CASE("walk_delete lazy match: MatchFn never called for structurally-rejected entries",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    int child = ops.add_dir();
    ops.dir(root).subdirs["subdir"] = child;
    ops.dir(root).entries = {
        DirEntry{"link", EntryMeta{EntryType::Symlink, 0, true}, 0, false},
        DirEntry{"junction", EntryMeta{EntryType::Reparse, 0, true}, 0, false},
        DirEntry{"other-device", EntryMeta{EntryType::RegularFile, 1, false}, 0, false},
        dir_entry("subdir"),
        DirEntry{"weird", EntryMeta{EntryType::Other, 0, true}, 0, false},
        DirEntry{"bad-stat", EntryMeta{}, 5, false},
        DirEntry{"bad-name", EntryMeta{EntryType::RegularFile, 1, true}, 0, true},
    };

    int match_calls = 0;
    MatchFn counting = [&](std::string_view) {
        ++match_calls;
        return true;
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, counting, kOpenLimits);

    REQUIRE(result.stop_reason == Reason::None);
    REQUIRE(match_calls == 0);
    // NameFilteredOut aside, every entry above is structurally decided
    // without ever needing the match result.
    REQUIRE(result.tally.entries_seen == 7);
}

TEST_CASE("walk_delete lazy match: MatchFn IS called for an otherwise-deletable file",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt")};

    int match_calls = 0;
    MatchFn counting = [&](std::string_view) {
        ++match_calls;
        return true;
    };

    walk_delete<FakeOps>(root, ops, counting, kOpenLimits);
    REQUIRE(match_calls == 1);
}

TEST_CASE("walk_delete lazy match: MatchFn not called past the entry cap", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("b.txt")};

    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 0;

    int match_calls = 0;
    MatchFn counting = [&](std::string_view) {
        ++match_calls;
        return true;
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, counting, limits);
    REQUIRE(match_calls == 0);
    REQUIRE(result.stop_reason == Reason::EntryCap);
}

// Regression: a NON-EMPTY batch truncated by the entry budget must still report
// EntryCap. The walker previously reported the cap only when the truncated batch
// came back empty, so a directory larger than max_entries processed its capped
// entries and then returned stop_reason None — telling the caller the tree had
// been exhaustively visited when it had not.
TEST_CASE("walk_delete: a non-empty truncated batch still reports EntryCap", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("b.txt"), file_entry("c.txt"),
                             file_entry("d.txt"), file_entry("e.txt")};

    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 3;

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, limits);
    REQUIRE(result.stop_reason == Reason::EntryCap);
    REQUIRE(result.tally.entries_seen <= 3);
    REQUIRE(result.entries.size() <= 3);
}

TEST_CASE("walk_delete: MatchFn throwing stops the walk with MatchError and keeps partial results",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("throws.txt"), file_entry("c.txt")};

    MatchFn throwing = [](std::string_view rel_path) -> bool {
        if (rel_path == "throws.txt")
            throw std::runtime_error("boom");
        return true;
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, throwing, kOpenLimits);

    REQUIRE(result.stop_reason == Reason::MatchError);
    // a.txt was deleted before the throw; c.txt was never reached.
    REQUIRE(result.entries.size() == 1);
    REQUIRE(result.entries[0].rel_path == "a.txt");
    REQUIRE(result.entries[0].status == EntryStatus::Deleted);
}

TEST_CASE("walk_delete: a stat_error entry is Failed(OsError) and never unlinked",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {DirEntry{"broken", EntryMeta{}, /*stat_error=*/13, false}};

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.entries.size() == 1);
    REQUIRE(result.entries[0].status == EntryStatus::Failed);
    REQUIRE(result.entries[0].reason == Reason::OsError);
    REQUIRE(result.entries[0].os_error == 13);
    REQUIRE(ops.unlink_calls_ == 0);
}

TEST_CASE("walk_delete: a name_invalid entry is Skipped(InvalidName) and MatchFn not called",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {
        DirEntry{"bad\x00name", EntryMeta{EntryType::RegularFile, 1, true}, 0, true}};

    int match_calls = 0;
    MatchFn counting = [&](std::string_view) {
        ++match_calls;
        return true;
    };

    DeleteResult result = walk_delete<FakeOps>(root, ops, counting, kOpenLimits);
    REQUIRE(match_calls == 0);
    REQUIRE(result.entries.size() == 1);
    REQUIRE(result.entries[0].status == EntryStatus::Skipped);
    REQUIRE(result.entries[0].reason == Reason::InvalidName);
}

TEST_CASE("walk_delete: an enumerate OsError fails that directory and siblings still walked",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    int broken_child = ops.add_dir();
    ops.dir(broken_child).enumerate_os_error = true;
    ops.dir(broken_child).enumerate_os_error_code = 5;

    int ok_child = ops.add_dir();
    ops.dir(ok_child).entries = {file_entry("sibling.txt")};

    ops.dir(root).subdirs["broken"] = broken_child;
    ops.dir(root).subdirs["ok"] = ok_child;
    ops.dir(root).entries = {dir_entry("broken"), dir_entry("ok")};

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.stop_reason == Reason::None);
    bool found_broken_failed = false;
    bool found_sibling_deleted = false;
    for (auto& e : result.entries) {
        if (e.rel_path == "broken" && e.status == EntryStatus::Failed &&
            e.reason == Reason::OsError && e.os_error == 5)
            found_broken_failed = true;
        if (e.rel_path == "ok/sibling.txt" && e.status == EntryStatus::Deleted)
            found_sibling_deleted = true;
    }
    REQUIRE(found_broken_failed);
    REQUIRE(found_sibling_deleted);
}

TEST_CASE("walk_delete: EnumBudget passthrough reflects max_entries minus entries_seen",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt")};

    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 42;

    walk_delete<FakeOps>(root, ops, always_match, limits);
    REQUIRE(ops.last_budget_.max_entries == 42); // entries_seen was 0 at the (only) enumerate call
}

TEST_CASE("walk_delete: wall-time truncation of enumeration stops immediately, nothing processed",
          "[confined_fs]") {
    auto start = std::chrono::steady_clock::now();
    FakeOps ops{start};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt")};

    DeleteLimits limits = kOpenLimits;
    limits.max_wall = std::chrono::milliseconds{0};
    ops.advance(std::chrono::milliseconds{1}); // now() >= deadline at first enumerate

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, limits);

    REQUIRE(result.stop_reason == Reason::WallTimeCap);
    REQUIRE(result.entries.empty());
    REQUIRE(ops.unlink_calls_ == 0);
}

TEST_CASE("walk_delete: NameFilteredOut entries are absent from output but counted",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt"), file_entry("b.txt")};

    DeleteResult result = walk_delete<FakeOps>(root, ops, never_match, kOpenLimits);

    REQUIRE(result.entries.empty());
    REQUIRE(result.tally.entries_seen == 2);
    REQUIRE(ops.unlink_calls_ == 0);
}

TEST_CASE("walk_delete: directories are never passed to unlink", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    int child = ops.add_dir();
    ops.dir(child).entries = {file_entry("leaf.txt")};
    ops.dir(root).subdirs["sub"] = child;
    ops.dir(root).entries = {dir_entry("sub")};

    walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    for (auto& name : ops.unlinked_names_)
        REQUIRE(name != "sub");
    REQUIRE(ops.unlinked_names_.size() == 1);
    REQUIRE(ops.unlinked_names_[0] == "leaf.txt");
}

TEST_CASE("walk_delete: open_dir policy refusal is Skipped, OsError refusal is Failed",
          "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).refusals["policy-refused"] = Reason::SymlinkRejected;
    ops.dir(root).os_errors_open["os-refused"] = 7;
    ops.dir(root).entries = {dir_entry("policy-refused"), dir_entry("os-refused")};

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.entries.size() == 2);
    auto find = [&](const std::string& name) -> const EntryOutcome& {
        for (auto& e : result.entries)
            if (e.rel_path == name)
                return e;
        throw std::runtime_error("not found");
    };
    REQUIRE(find("policy-refused").status == EntryStatus::Skipped);
    REQUIRE(find("policy-refused").reason == Reason::SymlinkRejected);
    REQUIRE(find("os-refused").status == EntryStatus::Failed);
    REQUIRE(find("os-refused").reason == Reason::OsError);
    REQUIRE(find("os-refused").os_error == 7);
}

TEST_CASE("walk_delete: unlink failure is Failed with the os_error preserved", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("a.txt", 999)};
    ops.fail_unlink_with(root, "a.txt", 42);

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.entries.size() == 1);
    REQUIRE(result.entries[0].status == EntryStatus::Failed);
    REQUIRE(result.entries[0].reason == Reason::OsError);
    REQUIRE(result.entries[0].os_error == 42);
    // bytes_deleted must not grow on a failed delete.
    REQUIRE(result.tally.bytes_deleted == 0);
}

TEST_CASE("walk_delete: bytes_deleted grows only on successful deletes", "[confined_fs]") {
    FakeOps ops{std::chrono::steady_clock::now()};
    int root = ops.add_dir();
    ops.dir(root).entries = {file_entry("ok.txt", 30), file_entry("bad.txt", 999)};
    ops.fail_unlink_with(root, "bad.txt", 1);

    DeleteResult result = walk_delete<FakeOps>(root, ops, always_match, kOpenLimits);

    REQUIRE(result.tally.bytes_deleted == 30);
}
