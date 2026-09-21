/**
 * pkg_inventory_legs.hpp — shared seam between the pkg_inventory plugin TU and
 * its three per-OS leg TUs.
 *
 * Holds the `Action` enum and its string conversions, the per-OS entry-point
 * declarations, and the ONE result-emission helper every leg calls (status row
 * first, then data rows, then the CC-07 typed status). Modelled on
 * peripherals_legs.hpp.
 *
 * Also holds the guarded POSIX walk primitives (`posix::`, bottom of the file)
 * the Linux and macOS walk shells share. They are excluded on Windows, so the
 * pure text/row layer (pkg_inventory_parsers.hpp) stays free of POSIX headers.
 */
#pragma once

#include "pkg_inventory_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <posix_dir_walk.hpp>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yuzu::pkg_inventory {

/// One value per `actions()` entry (pkg_inventory_plugin.cpp).
enum class Action { managers, packages };

[[nodiscard]] constexpr std::string_view action_name(Action a) noexcept {
    switch (a) {
    case Action::managers: return "managers";
    case Action::packages: return "packages";
    }
    return "managers";
}

/// nullopt for anything else, so the dispatcher can tell "unknown action" from
/// a real one.
[[nodiscard]] constexpr std::optional<Action> parse_action(std::string_view action) noexcept {
    if (action == "managers") return Action::managers;
    if (action == "packages") return Action::packages;
    return std::nullopt;
}

// ── per-OS entry points (defined by the leg TUs) ─────────────────────────
//
// Each is a READ and returns 0 unconditionally: a degraded read is not a
// failed command, and the degradation is reported through the status row and
// set_result_status. Declared unconditionally; only the DEFINITION is
// self-gated (each leg .cpp wraps its body in `#if defined(<os>)`), and the
// plugin TU calls only the host leg, so a single-OS build never needs the
// other two symbols to link.

int run_windows(yuzu::CommandContext& ctx, Action a);
int run_linux(yuzu::CommandContext& ctx, Action a);
int run_macos(yuzu::CommandContext& ctx, Action a);

// ── result emission ──────────────────────────────────────────────────────

/// Writes `status|...` FIRST, then every data row, then the CC-07 status. A
/// set `constraint` (comma-joined tokens from the walk) means at least one
/// acquisition step failed: status row `constrained` + CONSTRAINED/PARTIAL. No
/// constraint (including "manager/prefix absent, zero rows") is
/// `supported` + OK/FULL.
inline void emit_result(yuzu::CommandContext& ctx, Action a,
                        const std::vector<std::string>& data_rows,
                        const std::optional<std::string>& constraint) {
    const bool constrained = constraint.has_value();
    ctx.write_output(format_status_row(
        action_name(a), constrained ? StatusLevel::constrained : StatusLevel::supported,
        constrained ? std::string_view{*constraint} : std::string_view{}));
    for (const auto& row : data_rows)
        ctx.write_output(row);
    if (constrained)
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              *constraint);
    else
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
}

/// The by-design unsupported outcomes (Linux `packages`, both Windows legs):
/// `status|<action>|unsupported|<token>` and no data rows.
inline void emit_unsupported(yuzu::CommandContext& ctx, Action a, std::string_view token) {
    ctx.write_output(unsupported_status_row(action_name(a), token));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL, token);
}

// ── POSIX walk primitives (thin shell; not compiled on Windows) ──────────
//
// Shared by the Linux and macOS walk shells (pkg_inventory_{linux,macos}_parsers.hpp).
// Nothing here spawns a process: every read is open/openat/fstat/read/readdir
// with O_NOFOLLOW on the leaf, so a swapped-in symlink is refused rather than
// followed (private copies of the autoruns_macos.cpp open_dir_no_follow /
// read_file_bounded shapes). Guarded because posix_dir_walk.hpp does not exist
// on Windows; the portable row/text layer is pkg_inventory_parsers.hpp.
#if !defined(_WIN32)

namespace posix {

/// Move-only owner of a DIR*.
class Dir {
public:
    Dir() noexcept = default;
    explicit Dir(DIR* d) noexcept : d_(d) {}
    ~Dir() {
        if (d_ != nullptr) ::closedir(d_);
    }
    Dir(const Dir&) = delete;
    Dir& operator=(const Dir&) = delete;
    Dir(Dir&& o) noexcept : d_(o.d_) { o.d_ = nullptr; }
    Dir& operator=(Dir&& o) noexcept {
        if (this != &o) {
            if (d_ != nullptr) ::closedir(d_);
            d_ = o.d_;
            o.d_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] DIR* get() const noexcept { return d_; }
    [[nodiscard]] bool valid() const noexcept { return d_ != nullptr; }
    [[nodiscard]] int fd() const noexcept { return d_ != nullptr ? ::dirfd(d_) : -1; }

private:
    DIR* d_ = nullptr;
};

/// Outcome of an O_NOFOLLOW directory open. Exactly one of: opened (`dir`
/// valid), `absent` (ENOENT -- not this shell's error to report), or a real
/// constraint (`detail` non-empty).
struct OpenDirResult {
    Dir dir;
    bool absent = false;
    std::string_view detail{};
};

[[nodiscard]] inline OpenDirResult finish_dir_open(int fd) {
    OpenDirResult r;
    if (fd < 0) {
        const int err = errno;
        if (is_benign_absent_errno(err)) r.absent = true;
        else r.detail = open_failure_token(err);
        return r;
    }
    DIR* d = ::fdopendir(fd);
    if (d == nullptr) {
        const int err = errno;
        ::close(fd);
        if (is_benign_absent_errno(err)) r.absent = true;
        else r.detail = open_failure_token(err);
        return r;
    }
    r.dir = Dir{d};
    return r;
}

[[nodiscard]] inline OpenDirResult open_dir_no_follow(const std::string& path) {
    return finish_dir_open(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
}

[[nodiscard]] inline OpenDirResult open_dir_no_follow_at(const Dir& parent, const char* name) {
    return finish_dir_open(
        ::openat(parent.fd(), name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
}

/// Lists the entry names of an open directory (sorted, so output is
/// deterministic whatever readdir order the filesystem gives), capped at
/// `max_entries` (production: kMaxEntriesPerDir). `walk` reports truncation / a
/// mid-scan readdir error.
struct DirListing {
    std::vector<std::string> names;
    yuzu::shared::DirWalkResult walk;
};

[[nodiscard]] inline DirListing list_names(const Dir& dir, std::size_t max_entries) {
    DirListing out;
    out.walk = yuzu::shared::walk_dir_capped(dir.get(), max_entries,
                                             [&](const struct dirent* entry) {
                                                 out.names.emplace_back(entry->d_name);
                                                 return true;
                                             });
    std::sort(out.names.begin(), out.names.end());
    return out;
}

enum class EntryKind { directory, regular, symlink, other, error };

/// Classifies `name` inside `parent` without following a symlink: a real
/// directory, a regular file, a symlink (target not resolved), anything else
/// (fifo, socket, device, or a vanished entry -- ENOENT race) as `other`, and a
/// failed fstatat as `error` (with `detail` set). Homebrew walks accept only
/// `directory`; the config-source counts accept `regular` and `symlink`.
struct EntryClass {
    EntryKind kind = EntryKind::other;
    std::string_view detail{};
};

[[nodiscard]] inline EntryClass classify_entry(const Dir& parent, const char* name) {
    struct stat st{};
    if (::fstatat(parent.fd(), name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        const int err = errno;
        if (is_benign_absent_errno(err)) return {EntryKind::other, {}};
        return {EntryKind::error, open_failure_token(err)};
    }
    if (S_ISDIR(st.st_mode)) return {EntryKind::directory, {}};
    if (S_ISREG(st.st_mode)) return {EntryKind::regular, {}};
    if (S_ISLNK(st.st_mode)) return {EntryKind::symlink, {}};
    return {EntryKind::other, {}};
}

/// Bounded whole-file read of `path` (O_NOFOLLOW on the leaf), capped at
/// `max_bytes` (production: kMaxConfigBytes). O_NONBLOCK keeps the open of a
/// FIFO with no writer from blocking; the fstat regular-file check then rejects
/// it (`not_regular`) before any read.
struct FileRead {
    bool ok = false;            ///< `text` holds the (possibly capped) content
    bool absent = false;        ///< ENOENT
    bool oversized = false;     ///< file was larger than the cap; `text` is a prefix
    std::string_view detail{};  ///< non-empty => a real constraint
    std::string text;
};

[[nodiscard]] inline FileRead read_file_bounded(const std::string& path, std::size_t max_bytes) {
    FileRead r;
    const int fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        const int err = errno;
        if (is_benign_absent_errno(err)) r.absent = true;
        else r.detail = open_failure_token(err);
        return r;
    }
    struct FdGuard {
        int fd;
        ~FdGuard() { ::close(fd); }
    } guard{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        r.detail = open_failure_token(errno);
        return r;
    }
    if (!S_ISREG(st.st_mode)) {
        r.detail = "not_regular";
        return r;
    }
    const std::size_t size = static_cast<std::size_t>(st.st_size);
    const std::size_t want = size > max_bytes ? max_bytes : size;
    r.oversized = size > max_bytes;
    r.text.resize(want);
    std::size_t total = 0;
    while (total < want) {
        const ssize_t n = ::read(fd, r.text.data() + total, want - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            r.detail = open_failure_token(errno);
            r.text.clear();
            return r;
        }
        if (n == 0) break;
        total += static_cast<std::size_t>(n);
    }
    r.text.resize(total);
    r.ok = true;
    return r;
}

/// Records a directory-listing outcome into `acc`. Truncation and readdir
/// errors are real constraints (`entry_cap`, `enumeration_error`) -- the names
/// read so far are still usable by the caller, but the result is flagged
/// incomplete.
inline void note_listing(yuzu::shared::ConstraintAccumulator& acc, std::string_view os,
                         std::string_view source, const DirListing& l) {
    if (l.walk.enumeration_error) {
        acc.add_failure(make_token(os, source, "enumeration_error"));
        acc.mark_incomplete();
    }
    if (l.walk.truncated) {
        acc.add_failure(make_token(os, source, "entry_cap"));
        acc.mark_incomplete();
    }
}

} // namespace posix

#endif // !defined(_WIN32)

} // namespace yuzu::pkg_inventory
