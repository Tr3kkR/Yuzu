/**
 * privacy_permissions_macos.cpp -- macOS leg: TCC.db read-only, in-process (sqlite3_open_v2
 * SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_NOFOLLOW + PRAGMA query_only, the
 * app_usage_plugin.cpp precedent) -- never a `sqlite3` CLI shellout.
 *
 * TWO KINDS OF SOURCE, both read the same way:
 *   - the SYSTEM db, /Library/Application Support/com.apple.TCC/TCC.db -- machine-wide
 *     services (full_disk_access); rows unqualified.
 *   - one PER-USER db per real home, /Users/<name>/Library/Application Support/com.apple.TCC/
 *     TCC.db -- camera and microphone grants live HERE, not in the system db (empirically
 *     confirmed on this Mac, 2026-09-23: the per-user db held kTCCServiceMicrophone rows the
 *     system db never has). Rows are qualified `<name>\<client>` (qualify_app_id, the same
 *     shape the Windows leg uses per profile). Homes are enumerated the autoruns_macos.cpp
 *     collect_user_launchagents way: directories directly under /Users, not followed through a
 *     symlink, owned by uid >= 500, the directory name as the user name (no Open Directory call).
 * A per-user db that does not exist is `absent` for that user; a refusal (EPERM/EACCES on the
 * lstat, SQLITE_AUTH/PERM, or SQLITE_CANTOPEN whose underlying syscall failed EPERM/EACCES on a
 * file that IS there) is `denied`; anything else -- including a failed `PRAGMA query_only` or
 * query bind -- is `unreadable` with a `<source>:<cause>` token (macos_parsers.hpp decides; this
 * file only reads).
 *
 * RESIDUALS, stated rather than assumed away:
 *   - Every TCC.db (system AND per-user) is TCC-protected. An agent identity without Full Disk
 *     Access reads `denied` for every source -- the charter's expected outcome, recorded
 *     honestly; the production LaunchDaemon (root) is not known to hold FDA today.
 *   - A home outside /Users (a relocated or network home) is not read, and a user whose home
 *     directory is directly under /Users but owned by a uid < 500 is skipped as a system entry.
 *   - SQLITE_OPEN_NOFOLLOW refuses a symbolic link ANYWHERE in the path (SQLITE_CANTOPEN_SYMLINK,
 *     reported `unreadable`, never `denied`), but it checks by path before the open, so a user
 *     who controls their home can race it and make their own rows come from a different file.
 *     Attribution of per-user rows is therefore best-effort against that user; confinement of
 *     the READ is unaffected (read-only, query_only, no write).
 *   - The `access` schema and `auth_value` mapping (0=denied/2=allowed/3=limited) are the
 *     commonly-documented shape, proven on macOS 26.6.2 only; any other value is
 *     prompt_undetermined, never guessed.
 *
 * `location` is NOT queried here at all (CDX-R2-005) -- ADR-3003's platform investigation
 * established macOS Location Services is administered by `locationd`, OUTSIDE TCC; it ships as
 * one explicit `unsupported` row on every collection, whatever else failed.
 *
 * REAL PROBE, this Mac (`braga`, macOS 26.6.2), 2026-09-22, via the unit test binary's own
 * ambient identity (a Terminal/VSCode-launched process with FDA, NOT the production agent
 * identity): open + query against the system db's `access` table returned real
 * `full_disk_access` rows (auth_value 2 and 0).
 */
#include "privacy_permissions_legs.hpp"

#if defined(__APPLE__)

#include "privacy_permissions_macos_parsers.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sqlite3.h>

#include <posix_dir_walk.hpp>
#include <yuzu/agent/scoped_fd.hpp>

namespace yuzu::privacy_permissions {

namespace {

static_assert(macos::kSqlitePerm == SQLITE_PERM);
static_assert(macos::kSqliteCantOpen == SQLITE_CANTOPEN);
static_assert(macos::kSqliteAuth == SQLITE_AUTH);
static_assert(macos::kSqliteCantOpenSymlink == SQLITE_CANTOPEN_SYMLINK);

constexpr std::string_view kTccDbPath = "/Library/Application Support/com.apple.TCC/TCC.db";
constexpr std::string_view kUsersDir = "/Users";
constexpr std::string_view kUserTccRelPath = "/Library/Application Support/com.apple.TCC/TCC.db";
// Outer cap on /Users entries -- the same bounded-walk shape autoruns uses for its own /Users
// walk; a host with more than this many entries reports `users:truncated`, never silently.
constexpr std::size_t kMaxUserHomes = 4096;

class DbHandle {
public:
    DbHandle() noexcept = default;
    explicit DbHandle(sqlite3* db) noexcept : db_(db) {}
    ~DbHandle() {
        if (db_) sqlite3_close(db_);
    }
    DbHandle(const DbHandle&) = delete;
    DbHandle& operator=(const DbHandle&) = delete;
    DbHandle(DbHandle&& o) noexcept : db_(o.db_) { o.db_ = nullptr; }
    DbHandle& operator=(DbHandle&& o) noexcept {
        if (this != &o) {
            if (db_) sqlite3_close(db_);
            db_ = o.db_;
            o.db_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] sqlite3* get() const noexcept { return db_; }
    [[nodiscard]] explicit operator bool() const noexcept { return db_ != nullptr; }

private:
    sqlite3* db_{nullptr};
};

/// RAII owner for a prepared statement -- CDX-P1-007: the previous manual
/// `sqlite3_finalize` only at the end of the success path leaked `raw_stmt` (and left the
/// connection outstanding when `DbHandle::~DbHandle` ran `sqlite3_close`) on any exception
/// thrown while building a row between prepare and that single finalize call. Same shape as
/// `DbHandle` in this file and `detail::Stmt` in app_usage_parsers.hpp/`StmtPtr` in tar_db.cpp.
class StmtHandle {
public:
    StmtHandle() noexcept = default;
    explicit StmtHandle(sqlite3_stmt* stmt) noexcept : stmt_(stmt) {}
    ~StmtHandle() {
        if (stmt_) sqlite3_finalize(stmt_);
    }
    StmtHandle(const StmtHandle&) = delete;
    StmtHandle& operator=(const StmtHandle&) = delete;
    StmtHandle(StmtHandle&& o) noexcept : stmt_(o.stmt_) { o.stmt_ = nullptr; }
    StmtHandle& operator=(StmtHandle&& o) noexcept {
        if (this != &o) {
            if (stmt_) sqlite3_finalize(stmt_);
            stmt_ = o.stmt_;
            o.stmt_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] sqlite3_stmt* get() const noexcept { return stmt_; }
    [[nodiscard]] explicit operator bool() const noexcept { return stmt_ != nullptr; }

private:
    sqlite3_stmt* stmt_{nullptr};
};

/// sqlite3_errmsg, or a fixed literal when sqlite3 could not even allocate a handle.
std::string sqlite_errmsg(sqlite3* db) {
    return db ? std::string{sqlite3_errmsg(db)} : std::string{"no_handle"};
}

/// Opens `db_path` (default: the system TCC.db) read-only and makes the connection query-only.
/// On failure returns an empty handle and sets `failure` -- classified by
/// macos::classify_tcc_sqlite_failure from the real result code, the VFS's own failed-syscall
/// errno (sqlite3_system_errno) and sqlite3_errmsg, never a guessed diagnostic. A failed
/// `PRAGMA query_only=1` is a failure too: the source is never read without it. `db_path` is a
/// parameter so a unit test can force the exact open-failure branch deterministically against a
/// path this process genuinely cannot open, without a non-FDA identity or the real TCC.db.
DbHandle open_readonly(std::optional<macos::SourceFailure>& failure,
                       std::string_view db_path = kTccDbPath) {
    sqlite3* raw = nullptr;
    const int rc =
        sqlite3_open_v2(std::string{db_path}.c_str(), &raw,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_NOFOLLOW, nullptr);
    DbHandle db{raw}; // owns `raw` even on failure -- sqlite3 may allocate a handle just to
                      // carry the error message; RAII from here regardless of `rc`.
    if (rc != SQLITE_OK) {
        // The EXTENDED code: sqlite3_open_v2 returns only the primary one, and the
        // classifier must tell SQLITE_CANTOPEN_SYMLINK from a refused open.
        failure = macos::classify_tcc_sqlite_failure(
            macos::SqliteStage::open, db ? sqlite3_extended_errcode(db.get()) : rc,
            db ? sqlite3_system_errno(db.get()) : 0, sqlite_errmsg(db.get()));
        return DbHandle{};
    }
    sqlite3_busy_timeout(db.get(), 2000);
    const int pragma_rc = sqlite3_exec(db.get(), "PRAGMA query_only=1", nullptr, nullptr, nullptr);
    if (pragma_rc != SQLITE_OK) {
        failure = macos::classify_tcc_sqlite_failure(macos::SqliteStage::query_only, pragma_rc,
                                                     sqlite3_system_errno(db.get()),
                                                     sqlite_errmsg(db.get()));
        return DbHandle{};
    }
    return db;
}

/// Move-only RAII owner for a POSIX DIR* (autoruns_macos.cpp's DirHandle shape): closedir()s
/// exactly once, on every path, including an exception out of a walk callback. closedir() also
/// closes the fd fdopendir() adopted.
class DirHandle {
public:
    explicit DirHandle(DIR* d) noexcept : dir_(d) {}
    ~DirHandle() {
        if (dir_ != nullptr) ::closedir(dir_);
    }
    DirHandle(const DirHandle&) = delete;
    DirHandle& operator=(const DirHandle&) = delete;
    [[nodiscard]] DIR* get() const noexcept { return dir_; }
    [[nodiscard]] bool valid() const noexcept { return dir_ != nullptr; }

private:
    DIR* dir_;
};

/// Reads ONE TCC.db source (`owner` empty = the system db) into `rows`. Every outcome lands as
/// rows: a whole-source row when the file is missing/refused/unopenable/unpreparable, else
/// every mapped category's rows (macos::append_tcc_source_rows).
void read_tcc_source(std::string_view owner, const std::string& path, bool missing_is_absent,
                     std::vector<PermissionRow>& rows, yuzu::shared::ConstraintAccumulator& acc) {
    struct stat st{};
    const int lstat_errno = (::lstat(path.c_str(), &st) == 0) ? 0 : errno;
    if (const auto f = macos::classify_tcc_presence(lstat_errno, lstat_errno == 0 && S_ISREG(st.st_mode),
                                                    missing_is_absent)) {
        rows.push_back(macos::tcc_source_failed_row(owner, *f, acc));
        return;
    }

    std::optional<macos::SourceFailure> open_failure;
    DbHandle db = open_readonly(open_failure, path);
    if (!db) {
        rows.push_back(macos::tcc_source_failed_row(
            owner,
            open_failure.value_or(macos::SourceFailure{macos::SourceOutcome::unreadable,
                                                       "open_failed:unknown"}),
            acc));
        return;
    }

    sqlite3_stmt* raw_stmt = nullptr;
    static constexpr char kQuery[] =
        "SELECT service, client, auth_value FROM access WHERE service = ?";
    const int prep_rc = sqlite3_prepare_v2(db.get(), kQuery, -1, &raw_stmt, nullptr);
    StmtHandle stmt{raw_stmt}; // owns it from here -- finalized on every path, incl. an exception
    if (prep_rc != SQLITE_OK) {
        // 7.6: a TCC refusal can surface lazily, at the first page read, as CANTOPEN/AUTH --
        // classified the same as an open failure, never a flat `unreadable`.
        rows.push_back(macos::tcc_source_failed_row(
            owner,
            macos::classify_tcc_sqlite_failure(macos::SqliteStage::prepare,
                                               sqlite3_extended_errcode(db.get()),
                                               sqlite3_system_errno(db.get()),
                                               sqlite_errmsg(db.get())),
            acc));
        return;
    }

    std::vector<macos::TccServiceRead> reads;
    for (const auto& svc : macos::kTccServices) {
        macos::TccServiceRead read{svc.category, {}, false, false};
        sqlite3_reset(stmt.get()); // a prior step failure is already recorded on its own read
        if (sqlite3_bind_text(stmt.get(), 1, svc.service.data(),
                              static_cast<int>(svc.service.size()), SQLITE_STATIC) != SQLITE_OK) {
            read.bind_failed = true; // never run the statement with a stale or missing binding
            reads.push_back(std::move(read));
            continue;
        }
        for (;;) {
            const int step_rc = sqlite3_step(stmt.get());
            if (step_rc == SQLITE_DONE) break;
            if (step_rc != SQLITE_ROW) {
                read.step_failed = true;
                break;
            }
            const auto* client = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
            std::optional<int> auth_value;
            if (sqlite3_column_type(stmt.get(), 2) == SQLITE_INTEGER)
                auth_value = sqlite3_column_int(stmt.get(), 2);
            read.grants.push_back({client ? client : "-", auth_value});
        }
        reads.push_back(std::move(read));
    }
    macos::append_tcc_source_rows(owner, reads, rows, acc);
}

/// Real per-user homes directly under `users_dir` (autoruns_macos.cpp's
/// collect_user_launchagents rule, decided by macos::is_user_home_entry): a directory entry, not
/// a symlink, owned by uid >= 500, named by the directory itself. Failures that lose a whole
/// user or the whole walk are reported as rows (never silence); the returned names are sorted
/// for stable output. The fd and the DIR* are RAII-owned on every path, including an exception
/// out of the walk callback.
std::vector<std::string> enumerate_user_homes(std::vector<PermissionRow>& rows,
                                              yuzu::shared::ConstraintAccumulator& acc,
                                              const std::string& users_dir = std::string{kUsersDir}) {
    std::vector<std::string> names;
    yuzu::agent::ScopedFd fd{::open(users_dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (!fd) {
        const int err = errno;
        rows.push_back(failure_row("macos", "-", "-", err == EPERM || err == EACCES,
                                   "users:open_errno_" + std::to_string(err), acc));
        return names;
    }
    DirHandle dir{::fdopendir(fd.get())};
    if (!dir.valid()) {
        const int err = errno;
        rows.push_back(failure_row("macos", "-", "-", false,
                                   "users:fdopendir_errno_" + std::to_string(err), acc));
        return names; // `fd` still owns the descriptor and closes it
    }
    static_cast<void>(fd.release()); // the DIR* adopted the fd; closedir() closes it
    const auto walk = yuzu::shared::walk_dir_capped(dir.get(), kMaxUserHomes, [&](const struct dirent* e) {
        const std::string name{e->d_name};
        if (!macos::home_name_eligible(name)) return true;
        struct stat st{};
        if (::fstatat(::dirfd(dir.get()), e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            const int err = errno;
            if (err != ENOENT) // vanished between readdir and fstatat: nothing lost
                rows.push_back(failure_row("macos", qualify_app_id(name, "-"), "-",
                                           err == EPERM || err == EACCES,
                                           name + ":home_stat_errno_" + std::to_string(err), acc));
            return true;
        }
        if (macos::is_user_home_entry(name, S_ISDIR(st.st_mode),
                                      static_cast<std::uint32_t>(st.st_uid)))
            names.push_back(name);
        return true;
    });
    if (walk.truncated) rows.push_back(failure_row("macos", "-", "-", false, "users:truncated", acc));
    if (walk.enumeration_error)
        rows.push_back(failure_row("macos", "-", "-", false, "users:readdir_error", acc));
    std::sort(names.begin(), names.end());
    return names;
}

} // namespace

// `collect_macos_permissions` itself (below) is excluded when
// YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY is defined -- the seam
// test_privacy_permissions_macos_internals.cpp uses to #include this TU directly and reach the
// internal-linkage `open_readonly`/`read_tcc_source` for deterministic open-failure unit tests
// (denied-path composition, K2/COD-FV-5), without pulling collect_macos_permissions's own
// symbol into a second definition. This TU never statically links the real plugin either way
// (test_privacy_permissions_local_dispatcher.cpp loads it via PluginHandle::load/dlopen at
// runtime), so a second compilation of the same free functions here creates no ODR/duplicate-
// symbol conflict. Never defined by this TU's own (real) build -- meson.build does not set it.
// Mirrors autoruns_macos.cpp's identical seam for YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY
// and execution_artifacts_win.cpp's #4392 TU-inclusion precedent.
#ifndef YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY

int collect_macos_permissions(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;

    // The system db keeps its unqualified rows; a missing system db is `unreadable`, never absent.
    read_tcc_source({}, std::string{kTccDbPath}, /*missing_is_absent=*/false, rows, acc);

    for (const auto& user : enumerate_user_homes(rows, acc))
        read_tcc_source(user, std::string{kUsersDir} + "/" + user + std::string{kUserTccRelPath},
                        /*missing_is_absent=*/true, rows, acc);

    // Fixed four-category vocabulary (CDX-R2-005): location has no TCC service at all, so it
    // ships its own explicit `unsupported` row on EVERY collection -- including when every
    // TCC.db read above failed -- never silently omitted.
    rows.push_back({"macos", "-", "location", PermissionState::unsupported, "-", "-", "-", false});
    return emit_rows(ctx, rows, acc, false);
}

#endif // !YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY

} // namespace yuzu::privacy_permissions

#endif // defined(__APPLE__)
