/**
 * runtimes_linux_parsers.hpp -- the Linux leg's directory-walk layer for the
 * runtimes plugin, over an INJECTED ROOT (peripherals_linux_parsers.hpp shape:
 * production passes "/", the unit suite a materialized fixture tree).
 *
 * Two halves: a PORTABLE pure layer (failure tokens, errno -> token maps, path
 * helpers) that compiles on every OS, and a WALK SHELL (`#if !defined(_WIN32)`,
 * because agents/shared/posix_dir_walk.hpp is POSIX-only) holding
 * `dotnet_rows_at` / `jvm_rows_at` and the injected-root leg body
 * `run_linux_at`.
 *
 * WHAT IS READ (<root> + a literal, rung 1, zero subprocess):
 *   dotnet  usr/share/dotnet, usr/lib/dotnet, usr/lib64/dotnet:
 *           shared/<framework>/<version> and sdk/<version> directory names.
 *   jvm     usr/lib/jvm/<d>/release and opt/java/<d>/release (parse_release_file).
 *
 * SYMLINK SAFETY. Every directory is opened O_RDONLY|O_DIRECTORY|O_NOFOLLOW
 * (private copy of autoruns_macos.cpp's open_dir_no_follow_checked /
 * open_dir_no_follow_at_checked + dir_open_outcome_from_fd trichotomy),
 * hop-by-hop with openat from an already-open parent; entries are enumerated
 * with yuzu::shared::walk_dir_capped. The std::filesystem directory iterator is
 * never used. A symlink is never followed.
 *
 * A REFUSED SYMLINK IS NEVER AN EMPTY SUCCESS. A symlink at a candidate root
 * (or on the way to one) is a silent ALIAS only when its link text lexically
 * names ANOTHER candidate of the same action and that candidate is not itself
 * a symlink: whatever is there (a real directory, nothing at all, or an
 * unreadable directory that is then reported) is reached through that
 * candidate's own path, so the alias adds nothing (Fedora /usr/share/dotnet ->
 * ../lib64/dotnet; Arch /usr/lib64 -> lib, with or without a .NET install).
 * Any other refused candidate -- target outside the candidate set, a cycle or
 * a chain of aliases, an unreadable link, a symlinked injected root -- records
 * `symlink_refused` (constrained), as does a symlinked fixed `shared` / `sdk`
 * subdirectory and a symlinked `release` file.
 *
 * ENUMERATED ENTRY SYMLINKS ARE SKIPPED SILENTLY (a framework, version or JVM
 * home that is itself a symlink, including one swapped in between listing and
 * open, which the O_NOFOLLOW open classifies as an alias): distribution alias
 * entries (Debian default-java and java-1.17.0-openjdk-*, Fedora java ->
 * /etc/alternatives) are pervasive and their real directory is a sibling
 * entry. Documented gap: a runtime reachable ONLY through such an entry
 * symlink is not inventoried.
 *
 * FAILURE NEVER READS AS ABSENT. A genuinely absent directory (ENOENT) is
 * `supported` + zero rows; any other failed open/stat/read records a
 * `linux:runtimes:<reason>` token in the caller's ConstraintAccumulator, shared
 * across every root of an action, so a later successful root never erases an
 * earlier failure. Work is bounded: kMaxDirEntries per directory (`truncated`),
 * kMaxReleaseBytes per `release` (`release_oversize`).
 */
#pragma once

#include "runtimes_legs.hpp"
#include "runtimes_parsers.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <yuzu/agent/scoped_fd.hpp> // yuzu::agent::ScopedFd (agents/core; POSIX-only header)

#include <posix_dir_walk.hpp> // yuzu::shared::walk_dir_capped (agents/shared)

#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yuzu::runtimes::lnx {

// -- failure tokens ------------------------------------------------------------
//
// All match ^linux:[a-z0-9_]+(:[a-z0-9_]+)*$ (the plugin-wide leg-token grammar).

inline constexpr std::string_view kTokPermissionDenied = "linux:runtimes:permission_denied";
inline constexpr std::string_view kTokSymlinkRefused = "linux:runtimes:symlink_refused";
inline constexpr std::string_view kTokNotADirectory = "linux:runtimes:not_a_directory";
inline constexpr std::string_view kTokDirOpenFailed = "linux:runtimes:dir_open_failed";
inline constexpr std::string_view kTokStatFailed = "linux:runtimes:stat_failed";
inline constexpr std::string_view kTokReadFailed = "linux:runtimes:read_failed";
inline constexpr std::string_view kTokTruncated = "linux:runtimes:truncated";
inline constexpr std::string_view kTokNotARegularFile = "linux:runtimes:not_a_regular_file";
inline constexpr std::string_view kTokReleaseOversize = "linux:runtimes:release_oversize";
inline constexpr std::string_view kTokReleaseUnparsable = "linux:runtimes:release_unparsable";

/// Per-directory entry cap (`truncated` when more real entries remain).
inline constexpr std::size_t kMaxDirEntries = 16384;
/// `release` read bound.
inline constexpr std::size_t kMaxReleaseBytes = 64 * 1024;

// -- portable pure layer ---------------------------------------------------------

/// errno from a failed open/openat of a DIRECTORY -> reason token; nullopt for
/// ENOENT (genuinely absent: not a failure). ENOTDIR is a real constraint (a
/// non-directory where a directory was expected); the walk shell classifies a
/// symlink (an alias) BEFORE reaching this map.
[[nodiscard]] inline std::optional<std::string_view> dir_open_errno_token(int err) noexcept {
    switch (err) {
    case ENOENT: return std::nullopt;
    case EACCES:
    case EPERM:  return kTokPermissionDenied;
    case ELOOP:  return kTokSymlinkRefused;
    case ENOTDIR: return kTokNotADirectory;
    default:     return kTokDirOpenFailed;
    }
}

/// errno from a failed fstatat on a directory entry -> reason token; nullopt
/// for ENOENT (the entry vanished between listing and stat: a race, not a
/// failure).
[[nodiscard]] inline std::optional<std::string_view> stat_errno_token(int err) noexcept {
    switch (err) {
    case ENOENT: return std::nullopt;
    case EACCES:
    case EPERM:  return kTokPermissionDenied;
    case ELOOP:  return kTokSymlinkRefused;
    default:     return kTokStatFailed;
    }
}

/// errno from a failed open of a regular FILE (`release`) -> reason token;
/// nullopt for ENOENT (no such file: this directory is not a JVM home).
[[nodiscard]] inline std::optional<std::string_view> file_open_errno_token(int err) noexcept {
    switch (err) {
    case ENOENT: return std::nullopt;
    case EACCES:
    case EPERM:  return kTokPermissionDenied;
    case ELOOP:  return kTokSymlinkRefused;
    default:     return kTokReadFailed;
    }
}

/// `dir` + "/" + `name`, avoiding a doubled slash when dir is "/".
[[nodiscard]] inline std::string join_logical(std::string_view dir, std::string_view name) {
    std::string out{dir};
    if (out.empty() || out.back() != '/') out += '/';
    out.append(name);
    return out;
}

/// Candidate roots (root-relative, normalised), grouped by what they hold. A
/// symlinked candidate is an alias only of another candidate in ITS group.
inline constexpr std::array<std::string_view, 3> kDotnetRoots{"usr/share/dotnet", "usr/lib/dotnet",
                                                              "usr/lib64/dotnet"};
inline constexpr std::array<std::string_view, 2> kJvmRoots{"usr/lib/jvm", "opt/java"};

/// Lexically normalises a root-relative path: empty and `.` components dropped,
/// `..` pops one. nullopt when a `..` would climb above the root. Pure text --
/// nothing is resolved on disk.
[[nodiscard]] inline std::optional<std::string> normalize_rel(std::string_view path) {
    std::vector<std::string_view> parts;
    std::size_t pos = 0;
    while (pos <= path.size()) {
        auto sl = path.find('/', pos);
        if (sl == std::string_view::npos) sl = path.size();
        const auto comp = path.substr(pos, sl - pos);
        pos = sl + 1;
        if (comp.empty() || comp == ".") continue;
        if (comp == "..") {
            if (parts.empty()) return std::nullopt;
            parts.pop_back();
            continue;
        }
        parts.push_back(comp);
    }
    std::string out;
    for (const auto c : parts) {
        if (!out.empty()) out += '/';
        out.append(c);
    }
    return out;
}

/// Where a symlink found at <parent_rel>/<name> (link text `target`) would send
/// a walk that still had `remaining` components to go, as a normalised
/// root-relative path. An absolute target is read from the injected root.
/// nullopt if it climbs above the root. Never touches the filesystem.
[[nodiscard]] inline std::optional<std::string> alias_target_rel(std::string_view parent_rel,
                                                                 std::string_view target,
                                                                 std::string_view remaining) {
    std::string joined;
    if (!target.empty() && target.front() == '/') joined = std::string{target};
    else joined = std::string{parent_rel} + "/" + std::string{target};
    if (!remaining.empty()) joined += "/" + std::string{remaining};
    return normalize_rel(joined);
}

// -- POSIX walk shell ------------------------------------------------------------

#if !defined(_WIN32)

namespace walk {

using yuzu::shared::ConstraintAccumulator;

/// Move-only RAII owner for a POSIX DIR* (closes its fd too).
class DirHandle {
public:
    DirHandle() noexcept = default;
    explicit DirHandle(DIR* d) noexcept : dir_(d) {}
    ~DirHandle() { reset(); }
    DirHandle(const DirHandle&) = delete;
    DirHandle& operator=(const DirHandle&) = delete;
    DirHandle(DirHandle&& o) noexcept : dir_(o.dir_) { o.dir_ = nullptr; }
    DirHandle& operator=(DirHandle&& o) noexcept {
        if (this != &o) {
            reset();
            dir_ = o.dir_;
            o.dir_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] DIR* get() const noexcept { return dir_; }
    [[nodiscard]] explicit operator bool() const noexcept { return dir_ != nullptr; }

private:
    void reset() noexcept {
        if (dir_ != nullptr) ::closedir(dir_);
        dir_ = nullptr;
    }
    DIR* dir_ = nullptr;
};

/// Outcome of one directory open: `opened`, `absent` (ENOENT), `alias` (the
/// component is a symlink -- skipped, never followed) or `failed` (+ token).
enum class OpenStatus { opened, absent, alias, failed };

struct Opened {
    DirHandle dir;
    OpenStatus status = OpenStatus::absent;
    std::string_view token{}; // set iff status == failed
};

constexpr int kDirFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

/// Completes an already-attempted open (`fd`, errno current if fd < 0) of
/// `name` relative to `stat_dirfd`: fdopendir on success; on failure ENOENT =
/// absent, a symlink at that exact component = alias (classified by fstatat,
/// not by errno: Linux returns ENOTDIR and BSD/macOS ELOOP for
/// O_DIRECTORY|O_NOFOLLOW on a symlink), anything else = a constraint.
inline Opened finish_dir_open(int fd, int stat_dirfd, const char* name) {
    Opened o;
    if (fd < 0) {
        const int err = errno;
        if (err == ENOENT) return o; // absent
        struct stat st{};
        if (::fstatat(stat_dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode)) {
            o.status = OpenStatus::alias;
            return o;
        }
        o.status = OpenStatus::failed;
        o.token = dir_open_errno_token(err).value_or(kTokDirOpenFailed);
        return o;
    }
    yuzu::agent::ScopedFd owned{fd}; // closed on the failure path below
    DIR* d = ::fdopendir(owned.get());
    if (d == nullptr) {
        const int err = errno; // read before ScopedFd's close can disturb it
        o.status = OpenStatus::failed;
        o.token = dir_open_errno_token(err).value_or(kTokDirOpenFailed);
        return o;
    }
    (void)owned.release(); // fdopendir() succeeded: the DIR* owns the fd now
    o.dir = DirHandle{d};
    o.status = OpenStatus::opened;
    return o;
}

/// The injected root itself (O_NOFOLLOW checks its final component only).
inline Opened open_root(const std::string& root) {
    return finish_dir_open(::open(root.c_str(), kDirFlags), AT_FDCWD, root.c_str());
}

/// One path component via openat from an already-open parent.
inline Opened open_child(DIR* parent, const std::string& name) {
    const int pfd = ::dirfd(parent);
    return finish_dir_open(::openat(pfd, name.c_str(), kDirFlags), pfd, name.c_str());
}

/// Records a failed open in `acc`; absent is silent, and so is an alias unless
/// `refuse_alias` (a fixed subdirectory that nothing else covers). Returns the
/// handle (invalid unless the open succeeded).
inline DirHandle take_or_record(Opened&& o, ConstraintAccumulator& acc, bool refuse_alias = false) {
    if (o.status == OpenStatus::failed) acc.add_failure(o.token);
    else if (o.status == OpenStatus::alias && refuse_alias) acc.add_failure(kTokSymlinkRefused);
    return o.status == OpenStatus::opened ? std::move(o.dir) : DirHandle{};
}

/// Where a hop-by-hop path walk stopped.
struct PathWalk {
    DirHandle dir;                                 // the final directory iff status == opened
    OpenStatus status = OpenStatus::absent;
    std::string_view token{};                      // set iff status == failed
    DirHandle parent;                              // open holder of `comp` (alias / failure past the root)
    std::string parent_rel, comp, remaining;       // root-relative holder path, stopping component, the rest
};

/// Opens <root>/<rel> hop-by-hop ("usr/share/dotnet" -> usr, share, dotnet),
/// each hop O_NOFOLLOW from the previous fd, and reports where it stopped.
inline PathWalk walk_path(const std::string& root, std::string_view rel) {
    PathWalk w;
    Opened cur = open_root(root);
    if (cur.status != OpenStatus::opened) {
        w.status = cur.status; // the injected root itself: comp stays empty
        w.token = cur.token;
        return w;
    }
    std::string walked;
    std::size_t pos = 0;
    while (pos < rel.size()) {
        auto sl = rel.find('/', pos);
        if (sl == std::string_view::npos) sl = rel.size();
        const std::string comp{rel.substr(pos, sl - pos)};
        pos = sl + 1;
        if (comp.empty()) continue;
        Opened next = open_child(cur.dir.get(), comp);
        if (next.status != OpenStatus::opened) {
            w.status = next.status;
            w.token = next.token;
            w.parent = std::move(cur.dir);
            w.parent_rel = walked;
            w.comp = comp;
            if (pos < rel.size()) w.remaining = std::string{rel.substr(pos)};
            return w;
        }
        walked = walked.empty() ? comp : walked + "/" + comp;
        cur = std::move(next);
    }
    w.status = OpenStatus::opened;
    w.dir = std::move(cur.dir);
    return w;
}

/// True iff the symlink `w` stopped at is a benign alias: its link text
/// lexically names ANOTHER candidate in `candidates` and that candidate is not
/// itself a symlink, so whatever is (or is not) there is reached, and any
/// failure reported, through that candidate's own walk. Anything else
/// (unreadable or truncated link, a target outside the candidate set, a cycle
/// or a chain of aliases) is not covered. MUTATION: requiring the target to
/// OPEN (`== OpenStatus::opened`) turns a dangling in-set alias -- Arch's
/// /usr/lib64 -> lib with no .NET installed -- into a false `constrained`; the
/// dangling-alias case in test_runtimes_linux_parsers.cpp pins this.
inline bool alias_is_covered(const std::string& root, const PathWalk& w, std::string_view rel,
                             std::span<const std::string_view> candidates) {
    if (!w.parent || w.comp.empty()) return false; // a symlinked injected root is never an alias
    char buf[4096];
    const ssize_t n = ::readlinkat(::dirfd(w.parent.get()), w.comp.c_str(), buf, sizeof buf);
    if (n <= 0 || static_cast<std::size_t>(n) == sizeof buf) return false;
    const auto target = alias_target_rel(w.parent_rel, std::string_view{buf, static_cast<std::size_t>(n)},
                                         w.remaining);
    if (!target || *target == rel) return false;
    if (std::find(candidates.begin(), candidates.end(), std::string_view{*target}) == candidates.end())
        return false;
    return walk_path(root, *target).status != OpenStatus::alias;
}

/// Opens candidate root <root>/<rel> (a member of `candidates`). Absent and a
/// covered alias are silent; every other refusal is recorded in `acc`.
inline DirHandle open_path(const std::string& root, std::string_view rel,
                           std::span<const std::string_view> candidates,
                           ConstraintAccumulator& acc) {
    PathWalk w = walk_path(root, rel);
    switch (w.status) {
    case OpenStatus::opened: return std::move(w.dir);
    case OpenStatus::absent: break;
    case OpenStatus::failed: acc.add_failure(w.token); break;
    case OpenStatus::alias:
        if (!alias_is_covered(root, w, rel, candidates)) acc.add_failure(kTokSymlinkRefused);
        break;
    }
    return DirHandle{};
}

enum class EntryType { directory, symlink, other };

struct EntryInfo {
    std::string name;
    EntryType type = EntryType::other;
};

/// The real entries of an open directory, sorted by name (readdir order is
/// unspecified, and rows must be deterministic), reading at most `max_entries`
/// real entries (production: kMaxDirEntries; a parameter so the cap and its
/// `truncated` propagation are testable without 16k files). A vanished entry
/// (ENOENT) is skipped; any other stat failure, a hit cap and a readdir I/O
/// error are recorded.
inline std::vector<EntryInfo> list_entries(DIR* d, ConstraintAccumulator& acc,
                                           std::size_t max_entries) {
    std::vector<EntryInfo> out;
    const int fd = ::dirfd(d);
    const auto res = yuzu::shared::walk_dir_capped(d, max_entries, [&](const struct dirent* e) {
        struct stat st{};
        if (::fstatat(fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (const auto tok = stat_errno_token(errno)) acc.add_failure(*tok);
            return true;
        }
        EntryInfo info;
        info.name = std::string{e->d_name};
        info.type = S_ISDIR(st.st_mode)   ? EntryType::directory
                    : S_ISLNK(st.st_mode) ? EntryType::symlink
                                          : EntryType::other;
        out.push_back(std::move(info));
        return true;
    });
    if (res.truncated) acc.add_failure(kTokTruncated);
    if (res.enumeration_error) acc.add_failure(kTokReadFailed);
    std::sort(out.begin(), out.end(),
              [](const EntryInfo& a, const EntryInfo& b) { return a.name < b.name; });
    return out;
}

enum class ReadStatus { ok, absent, failed };

struct ReadResult {
    ReadStatus status = ReadStatus::absent;
    std::string text;
    std::string_view token{}; // set iff status == failed
};

/// Reads the regular file `name` under the open directory `dirfd`, refusing a
/// symlink (O_NOFOLLOW), a non-regular file, and anything over `max_bytes`.
/// O_NONBLOCK so a FIFO planted as `release` can never hang the agent (it is
/// then refused by the S_ISREG check).
inline ReadResult read_file_bounded_at(int dirfd, const char* name, std::size_t max_bytes) {
    ReadResult r;
    const int fd = ::openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        const auto tok = file_open_errno_token(errno);
        if (!tok) return r; // absent
        r.status = ReadStatus::failed;
        r.token = *tok;
        return r;
    }
    const yuzu::agent::ScopedFd guard{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        r.status = ReadStatus::failed;
        r.token = kTokReadFailed;
        return r;
    }
    if (!S_ISREG(st.st_mode)) {
        r.status = ReadStatus::failed;
        r.token = kTokNotARegularFile;
        return r;
    }
    if (static_cast<unsigned long long>(st.st_size) > max_bytes) {
        r.status = ReadStatus::failed;
        r.token = kTokReleaseOversize;
        return r;
    }
    char buf[4096];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            r.status = ReadStatus::failed;
            r.token = kTokReadFailed;
            r.text.clear();
            return r;
        }
        if (n == 0) break;
        r.text.append(buf, static_cast<std::size_t>(n));
        if (r.text.size() > max_bytes) { // grew past the fstat size
            r.status = ReadStatus::failed;
            r.token = kTokReleaseOversize;
            r.text.clear();
            return r;
        }
    }
    r.status = ReadStatus::ok;
    return r;
}

} // namespace walk

// -- the three action walks ----------------------------------------------------------
//
// `max_entries` is the per-directory cap (production default kMaxDirEntries).

/// dotnet: <root>/{usr/share,usr/lib,usr/lib64}/dotnet -> shared/<fw>/<ver> and
/// sdk/<ver>. Row order: candidate-root order, then framework name, then
/// version (sorted).
[[nodiscard]] inline std::vector<std::string> dotnet_rows_at(
    const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
    std::size_t max_entries = kMaxDirEntries) {
    using namespace walk;
    std::vector<std::string> rows;
    const std::string root_s = root.string();
    for (const std::string_view rel : kDotnetRoots) {
        const DirHandle dotnet = open_path(root_s, rel, kDotnetRoots, acc);
        if (!dotnet) continue;
        const std::string logical = "/" + std::string{rel};

        if (const DirHandle shared =
                take_or_record(open_child(dotnet.get(), "shared"), acc, /*refuse_alias=*/true)) {
            for (const auto& fw : list_entries(shared.get(), acc, max_entries)) {
                if (fw.type != EntryType::directory) continue;
                const DirHandle fwh = take_or_record(open_child(shared.get(), fw.name), acc);
                if (!fwh) continue;
                for (const auto& ver : list_entries(fwh.get(), acc, max_entries)) {
                    if (ver.type != EntryType::directory) continue;
                    if (auto row = dotnet_row(fw.name, ver.name,
                                              join_logical(join_logical(logical + "/shared", fw.name),
                                                           ver.name)))
                        rows.push_back(std::move(*row));
                }
            }
        }
        if (const DirHandle sdk =
                take_or_record(open_child(dotnet.get(), "sdk"), acc, /*refuse_alias=*/true)) {
            for (const auto& ver : list_entries(sdk.get(), acc, max_entries)) {
                if (ver.type != EntryType::directory) continue;
                if (auto row = dotnet_row("sdk", ver.name, join_logical(logical + "/sdk", ver.name)))
                    rows.push_back(std::move(*row));
            }
        }
    }
    return rows;
}

/// jvm: <root>/{usr/lib/jvm,opt/java}/<d>/release. A directory without a
/// `release` file is not a JVM home (silent); an unreadable / oversized /
/// version-less one is a recorded constraint. Symlinked homes are aliases.
[[nodiscard]] inline std::vector<std::string> jvm_rows_at(
    const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc,
    std::size_t max_entries = kMaxDirEntries) {
    using namespace walk;
    std::vector<std::string> rows;
    const std::string root_s = root.string();
    for (const std::string_view rel : kJvmRoots) {
        const DirHandle jvm_dir = open_path(root_s, rel, kJvmRoots, acc);
        if (!jvm_dir) continue;
        const std::string logical = "/" + std::string{rel};
        for (const auto& home : list_entries(jvm_dir.get(), acc, max_entries)) {
            if (home.type != EntryType::directory) continue;
            const DirHandle hh = take_or_record(open_child(jvm_dir.get(), home.name), acc);
            if (!hh) continue;
            const auto rr = read_file_bounded_at(::dirfd(hh.get()), "release", kMaxReleaseBytes);
            if (rr.status == ReadStatus::absent) continue;
            if (rr.status == ReadStatus::failed) {
                acc.add_failure(rr.token);
                continue;
            }
            const auto row = jvm_row(parse_release_file(rr.text), join_logical(logical, home.name));
            if (!row) {
                acc.add_failure(kTokReleaseUnparsable);
                continue;
            }
            rows.push_back(*row);
        }
    }
    return rows;
}

/// The Linux leg's dispatch: the rows for action `a` under `root`, failures
/// recorded in `acc`. run_linux_at is this plus emit_read; both live here so the
/// action -> walk -> emit wiring is unit-testable without linking the plugin TU.
[[nodiscard]] inline std::vector<std::string> action_rows_at(
    Action a, const std::filesystem::path& root, yuzu::shared::ConstraintAccumulator& acc) {
    switch (a) {
    case Action::dotnet: return dotnet_rows_at(root, acc);
    case Action::jvm:    return jvm_rows_at(root, acc);
    }
    return {};
}

/// The Linux leg body with the filesystem root injected: `action_rows_at` plus
/// `emit_read` (status row first, then every data row, then the typed result
/// status). runtimes_linux.cpp's `run_linux` calls it with "/"; the unit suite
/// drives it over a materialized fixture tree through a real CommandContext
/// (LocalDispatcher), so what is asserted is the rows AND the status the command
/// actually reports. Returns 0 unconditionally: a degraded read is not a failed
/// command; the degradation rides the status row and set_result_status.
inline int run_linux_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root) {
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = action_rows_at(a, root, acc);
    emit_read(ctx, a, rows, acc);
    return 0;
}

#endif // !defined(_WIN32)

} // namespace yuzu::runtimes::lnx
