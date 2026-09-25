/**
 * test_privacy_permissions_macos_internals.cpp -- TU-inclusion seam over
 * privacy_permissions_macos.cpp's internal-linkage `open_readonly` and `read_tcc_source`
 * (K2/COD-FV-5, both external code-review reviewers independently: the binding contract's single
 * most important property -- a refused TCC.db open must never collapse into `absent` -- was
 * proven only at the pure layer, never against the real open this leg actually makes).
 *
 * Both take the db path as a parameter (default: the real TCC.db) specifically so this test can
 * force each outcome branch deterministically, without a non-FDA identity and without touching
 * any real TCC.db: a missing per-user db must read `absent`, a missing SYSTEM db `unreadable`, a
 * present-but-unopenable file (mode 000, the same refusal an SIP/TCC denial produces) `denied`
 * -- never absent -- and a hostile file (view, WAL, sidecar, oversized) is bounded or refused.
 * Every database here is synthetic, built under a TempDir; the deadline is an injected budget,
 * never a sleep.
 *
 * #if defined(__APPLE__) guards the WHOLE body -- empty TU elsewhere, mirroring every other
 * Apple-only internals-seam test in this tree (test_autoruns_macos_local.cpp's #4241 seam is the
 * direct precedent this file copies).
 */
#if !defined(__APPLE__)

// Nothing to test off macOS -- see the file banner above.

#else // defined(__APPLE__)

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "test_helpers.hpp"

// Direct source inclusion, macOS-only, mirroring autoruns_macos.cpp's
// YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY seam (see that file's own banner, and
// YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY's definition comment in
// privacy_permissions_macos.cpp): `open_readonly`, `read_tcc_source` and `snapshot_fd` have
// internal (anonymous-namespace) linkage, so there is no header seam to reach them through
// otherwise. This TU never statically links the real plugin either way
// (test_privacy_permissions_local_dispatcher.cpp loads it via PluginHandle::load/dlopen at
// runtime), so a second compilation of the same free functions here creates no ODR/duplicate-
// symbol conflict.
// Excluding collect_macos_permissions leaves enumerate_user_homes with no caller in THIS
// compilation of the TU -- real, used call sites in the actual (non-test) build of this same
// file. -Wunused-function is non-fatal project-wide but is silenced narrowly here, scoped to just
// the include.
#define YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY 1
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#include "../../agents/plugins/privacy_permissions/src/privacy_permissions_macos.cpp"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#undef YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY

namespace yuzu::privacy_permissions {

namespace {

constexpr std::string_view kAccessSchema =
    "CREATE TABLE access(service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER, "
    "PRIMARY KEY(service, client, client_type));";

// Canonical: the temp dir sits under the /var -> /private/var symlink O_NOFOLLOW_ANY refuses.
std::filesystem::path scratch_dir(const yuzu::test::TempDir& tmp) {
    std::filesystem::create_directories(tmp.path);
    return std::filesystem::canonical(tmp.path);
}

void make_db(const std::filesystem::path& path, const std::string& sql) {
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                            nullptr) == SQLITE_OK);
    const DbPtr db{raw};
    REQUIRE(sqlite3_exec(db.get(), sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}

std::vector<std::string> listing(const std::filesystem::path& dir) {
    std::vector<std::string> names;
    for (const auto& e : std::filesystem::directory_iterator(dir))
        names.push_back(e.path().filename().string());
    std::sort(names.begin(), names.end());
    return names;
}

struct SourceRead {
    std::vector<PermissionRow> rows;
    yuzu::shared::ConstraintAccumulator acc;

    [[nodiscard]] std::size_t count(std::string_view category, PermissionState state) const {
        return static_cast<std::size_t>(std::count_if(rows.begin(), rows.end(), [&](const auto& r) {
            return r.category == category && r.state == state;
        }));
    }
    [[nodiscard]] bool has_raw(std::string_view raw) const {
        return std::any_of(rows.begin(), rows.end(), [&](const auto& r) { return r.raw == raw; });
    }
};

SourceRead read_source(const std::filesystem::path& db, const macos::ReadBounds& bounds = {}) {
    SourceRead r;
    read_tcc_source("evil", db.string(), /*missing_is_absent=*/true, r.rows, r.acc, bounds);
    return r;
}

} // namespace

TEST_CASE("privacy_permissions macOS: open_readonly on a genuinely unopenable path fails "
          "through the same generic path a real TCC/SIP denial would, with a real "
          "sqlite3_errmsg diagnostic",
          "[privacy_permissions][macos][internals]") {
    std::optional<macos::SourceFailure> failure;
    auto db = open_readonly(failure, "/nonexistent/deliberately-broken/privacy_permissions_test.db");
    CHECK_FALSE(static_cast<bool>(db));
    REQUIRE(failure.has_value());
    CHECK(failure->cause.rfind("open_failed:", 0) == 0);
    CHECK(failure->cause.size() > std::string_view{"open_failed:"}.size());
    // A missing parent directory is SQLITE_CANTOPEN with ENOENT from the VFS -- not a refusal.
    CHECK(failure->outcome == macos::SourceOutcome::unreadable);
}

TEST_CASE("privacy_permissions macOS: read_tcc_source on a MISSING per-user db is one absent "
          "row with no token; a missing SYSTEM db is unreadable, never absent",
          "[privacy_permissions][macos][internals]") {
    const std::string missing =
        yuzu::test::unique_temp_path("yuzu_test_pp_missing_").string() + "/TCC.db";

    yuzu::shared::ConstraintAccumulator user_acc;
    std::vector<PermissionRow> user_rows;
    read_tcc_source("alice", missing, /*missing_is_absent=*/true, user_rows, user_acc);
    REQUIRE(user_rows.size() == 1);
    CHECK(format_row(user_rows[0]) == "permissions|macos|alice/-|-|absent|-|-|-");
    CHECK_FALSE(user_acc.any_failure());

    yuzu::shared::ConstraintAccumulator sys_acc;
    std::vector<PermissionRow> sys_rows;
    read_tcc_source({}, missing, /*missing_is_absent=*/false, sys_rows, sys_acc);
    REQUIRE(sys_rows.size() == 1);
    CHECK(sys_rows[0].state == PermissionState::unreadable);
    CHECK(sys_rows[0].raw == "tcc_db:missing");
    CHECK(select_status(sys_acc, any_denied(sys_rows), false).status ==
          YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("privacy_permissions macOS: read_tcc_source on a PRESENT file the process cannot open "
          "(mode 000 -- the same SQLITE_CANTOPEN a TCC refusal produces) is denied and promotes "
          "PERMISSION_DENIED, never absent",
          "[privacy_permissions][macos][internals]") {
    if (::geteuid() == 0) SKIP("root ignores mode 000 -- the refusal cannot be forced here");
    yuzu::test::TempDir tmp{"yuzu_test_pp_tcc_"};
    const auto path = scratch_dir(tmp) / "TCC.db";
    { std::ofstream{path} << "x"; }
    REQUIRE(::chmod(path.c_str(), 0) == 0);

    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    read_tcc_source("alice", path.string(), /*missing_is_absent=*/true, rows, acc);

    REQUIRE(rows.size() == 1);
    CHECK(rows[0].app_id == "alice\\-");
    CHECK(rows[0].state == PermissionState::denied);
    CHECK(rows[0].read_denied);
    CHECK(rows[0].raw.rfind("alice:tcc_db:open_failed:", 0) == 0);
    const auto st = select_status(acc, any_denied(rows), false);
    CHECK(st.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

TEST_CASE("privacy_permissions macOS: read_tcc_source through a SYMLINKED directory is refused by "
          "O_NOFOLLOW_ANY as unreadable, never a false denied",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_link_"};
    const auto base = scratch_dir(tmp); // no symlink but the one below
    const auto real_dir = base / "real";
    const auto link_dir = base / "link";
    std::filesystem::create_directories(real_dir);
    std::filesystem::create_directory_symlink(real_dir, link_dir);
    make_db(real_dir / "TCC.db", std::string{kAccessSchema});

    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    read_tcc_source("alice", (link_dir / "TCC.db").string(), /*missing_is_absent=*/true, rows, acc);

    REQUIRE(rows.size() == 1);
    CHECK(rows[0].state == PermissionState::unreadable);
    CHECK_FALSE(rows[0].read_denied);
    CHECK(rows[0].raw == "alice:tcc_db:open_failed:symlink");
    CHECK(select_status(acc, any_denied(rows), false).status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("privacy_permissions macOS: a db reads sorted, whatever the path's spelling, "
          "with a 64-bit auth_value and hostile bytes sanitized, and the directory is untouched",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_honest_"};
    const auto dir = scratch_dir(tmp) / "q?x# h%20";
    std::filesystem::create_directories(dir);
    make_db(dir / "TCC.db", // a view: scan order is the UNION order, so the sort is observable
            "CREATE VIEW access AS SELECT 'kTCCServiceCamera' AS service, CAST(x'C328FF41' AS TEXT) "
            "AS client, 0 AS client_type, 2 AS auth_value UNION ALL SELECT 'kTCCServiceCamera', "
            "'b.app', 0, 4294967298 UNION ALL SELECT 'kTCCServiceCamera', 'a.app', 0, 0;");
    const auto before = listing(dir);

    std::optional<macos::SourceFailure> failure;
    CHECK(open_readonly(failure, (dir / "TCC.db").string())); // the URI builder round-trips it
    const auto r = read_source(dir / "TCC.db");
    REQUIRE(r.rows.size() == 5);
    CHECK(format_row(r.rows[0]) == "permissions|macos|evil/a.app|camera|denied|0|-|-");
    CHECK(r.rows[1].state == PermissionState::prompt_undetermined);
    CHECK(r.rows[1].raw == "4294967298");
    CHECK(format_row(r.rows[2]) == "permissions|macos|evil/\xEF\xBF\xBD(\xEF\xBF\xBD"
                                   "A|camera|allowed|2|-|-"); // split: 'A' extends a hex escape
    CHECK(r.count("microphone", PermissionState::absent) == 1);
    CHECK_FALSE(r.acc.any_failure());
    CHECK(listing(dir) == before);
}

TEST_CASE("privacy_permissions macOS: a hostile view is cut at the row cap, never read to the end",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_view_"};
    const auto db = scratch_dir(tmp) / "TCC.db";
    make_db(db,
            "CREATE VIEW access AS WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n "
            "LIMIT 5000) SELECT 'kTCCServiceCamera' AS service, 'c'||i AS client, 0 AS "
            "client_type, 2 AS auth_value FROM n;");

    const auto r = read_source(db);
    CHECK(r.count("camera", PermissionState::allowed) == macos::kMaxRowsPerService);
    CHECK(r.has_raw("evil:tcc_db:camera:row_cap"));
    CHECK(r.rows.size() <= macos::kMaxRowsPerService + 3);
    CHECK(select_status(r.acc, any_denied(r.rows), false).status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("privacy_permissions macOS: anything that is not one quiescent rollback-mode SQLite file "
          "is refused with a named cause, and nothing is created or opened beside it",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_refuse_"};
    const auto dir = scratch_dir(tmp);
    const auto db = dir / "TCC.db";
    const std::string honest =
        std::string{kAccessSchema} + "INSERT INTO access VALUES('kTCCServiceCamera','a.app',0,2);";

    make_db(db, "PRAGMA journal_mode=WAL;" + honest);
    const auto before = listing(dir);
    CHECK(read_source(db).rows.at(0).raw == "evil:tcc_db:wal_mode");
    CHECK(listing(dir) == before);
    std::filesystem::remove(db);

    make_db(db, honest);
    for (const char* suffix : {"-wal", "-journal", "-shm"}) {
        { std::ofstream{db.string() + suffix}; }
        const auto with_sidecar = listing(dir);
        const auto r = read_source(db);
        INFO(suffix);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].raw == "evil:tcc_db:sidecar_present");
        CHECK(listing(dir) == with_sidecar);
        std::filesystem::remove(db.string() + suffix);
    }
    if (::mkfifo((db.string() + "-journal").c_str(), 0600) == 0) // lstat never opens it
        CHECK(read_source(db).rows.at(0).raw == "evil:tcc_db:sidecar_present");

    { std::ofstream{dir / "empty.db"}; }
    { std::ofstream{dir / "junk.db"} << std::string(300, 'x'); }
    REQUIRE(::mkfifo((dir / "fifo.db").c_str(), 0600) == 0);
    CHECK(read_source(dir / "empty.db").rows.at(0).raw == "evil:tcc_db:size_out_of_range");
    CHECK(read_source(dir / "junk.db").rows.at(0).raw == "evil:tcc_db:not_sqlite");
    CHECK(read_source(dir / "fifo.db").rows.at(0).raw == "evil:tcc_db:not_regular_file");
}

TEST_CASE("privacy_permissions macOS: the value limit lands after the schema loads, and an "
          "oversized record is one category's failure",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_big_"};
    const auto dir = scratch_dir(tmp);
    make_db(dir / "schema.db",
            "CREATE TABLE access(service TEXT, client TEXT, client_type INTEGER, auth_value "
            "INTEGER, PRIMARY KEY(service, client, client_type) /* " +
                std::string(macos::kMaxValueBytes + 1024, 'p') +
                " */);INSERT INTO access VALUES('kTCCServiceCamera','a.app',0,2);");
    const auto schema = read_source(dir / "schema.db");
    CHECK(schema.count("camera", PermissionState::allowed) == 1);
    CHECK_FALSE(schema.acc.any_failure());

    make_db(dir / "cell.db",
            std::string{kAccessSchema} + "INSERT INTO access VALUES('kTCCServiceCamera','" +
                std::string(2 * macos::kMaxValueBytes, 'c') +
                "',0,2);INSERT INTO access VALUES('kTCCServiceMicrophone','m.app',0,2);");
    const auto cell = read_source(dir / "cell.db");
    CHECK(cell.has_raw("evil:tcc_db:camera:value_too_long"));
    CHECK(cell.count("camera", PermissionState::absent) == 0);
    CHECK(cell.count("microphone", PermissionState::allowed) == 1);
}

TEST_CASE("privacy_permissions macOS: a spent run or source budget is a named timeout, never "
          "absent, and the installed progress handler interrupts an endless query",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_budget_"};
    const auto db = scratch_dir(tmp) / "TCC.db";
    make_db(db, std::string{kAccessSchema});

    macos::ReadBounds run_spent;
    run_spent.run_end = std::chrono::steady_clock::time_point{};
    CHECK(read_source(db, run_spent).rows.at(0).raw == "evil:tcc_db:timeout");

    macos::ReadBounds source_spent;
    source_spent.source_budget = std::chrono::steady_clock::duration::zero();
    const auto cut = read_source(db, source_spent);
    REQUIRE(cut.rows.size() == macos::kTccServices.size());
    for (const auto& svc : macos::kTccServices)
        CHECK(cut.has_raw("evil:tcc_db:" + std::string{svc.category} + ":timeout"));

    Deadline deadline{std::chrono::steady_clock::time_point{}};
    std::optional<macos::SourceFailure> failure;
    const DbPtr handle = open_readonly(failure, db.string(), &deadline);
    REQUIRE(handle);
    sqlite3_stmt* raw = nullptr;
    REQUIRE(sqlite3_prepare_v2(handle.get(),
                               "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n) "
                               "SELECT i FROM n WHERE i < 0",
                               -1, &raw, nullptr) == SQLITE_OK);
    const StmtPtr stmt{raw};
    CHECK(sqlite3_step(stmt.get()) == SQLITE_INTERRUPT);
    CHECK(deadline.fired);
}

TEST_CASE("privacy_permissions macOS: snapshot_fd sees a change made to the file through the "
          "held descriptor",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_snap_"};
    const auto db = scratch_dir(tmp) / "TCC.db";
    make_db(db, std::string{kAccessSchema});
    yuzu::agent::ScopedFd fd{::open(db.c_str(), O_RDONLY | O_CLOEXEC)};
    yuzu::agent::ScopedFd writer{::open(db.c_str(), O_WRONLY | O_CLOEXEC)};
    REQUIRE((fd && writer));

    const auto first = snapshot_fd(fd.get());
    REQUIRE(first);
    CHECK(macos::read_unchanged(first->stamp, snapshot_fd(fd.get())->stamp));
    const unsigned char bump[4] = {0, 0, 0, 9};
    REQUIRE(::pwrite(writer.get(), bump, sizeof bump, 24) == 4); // the change counter alone
    CHECK(snapshot_fd(fd.get())->stamp.change_counter == 9);
    CHECK_FALSE(macos::read_unchanged(first->stamp, snapshot_fd(fd.get())->stamp));
}

} // namespace yuzu::privacy_permissions

#endif // defined(__APPLE__)
