#ifndef _WIN32

/**
 * confined_fs_posix.cpp -- POSIX shell for confined recursive delete
 * (confined_fs.hpp's platform contract). Every operation past `open_root`
 * is PARENT-HANDLE-RELATIVE: `openat`/`fstatat`/`unlinkat` against an
 * already-open `dir_fd`, never a freshly `::open()`ed/`::stat()`ed path
 * below the root. The ONE exception is `openat(fd, ".")`, used both here
 * (delete_matching's root frame) and in `enumerate_at` below to obtain an
 * INDEPENDENT open-file-description over an already-held fd's own inode --
 * it resolves through that fd, not a path string, so it is not a re-
 * resolution and is exempt from the no-path-below-root rule (see
 * confined_fs.hpp's header banner).
 *
 * This TU carries NO duplicated walk/tally/deadline/cap policy: all of that
 * lives in confined_fs_walk.hpp's `walk_delete`, which `delete_matching`
 * below instantiates with a file-local `PosixOps` that does nothing beyond
 * adapt `open_dir_at`/`enumerate_at`/`unlink_at`/`steady_clock::now()` to
 * the `Ops` shape `walk_delete` expects (PLAN-010).
 */

#include <yuzu/agent/confined_fs.hpp>
#include <yuzu/agent/confined_fs_walk.hpp>

#include <spdlog/spdlog.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

namespace yuzu::agent::confined_fs {

namespace {

/// InvalidName rule (confined_fs.hpp banner, PLAN-015): refused BEFORE any
/// syscall touches the name -- checked against `std::string::size()` (via
/// `find`, which respects embedded NULs), never `strlen`, so a NUL-
/// truncation attempt is caught rather than silently shortening the name
/// the syscall actually receives.
bool is_invalid_name(const std::string& name) {
    if (name.empty() || name == "." || name == "..")
        return true;
    if (name.find('/') != std::string::npos)
        return true;
    if (name.find('\0') != std::string::npos)
        return true;
    return false;
}

EntryType classify_mode(mode_t mode) {
    if (S_ISREG(mode))
        return EntryType::RegularFile;
    if (S_ISDIR(mode))
        return EntryType::Directory;
    if (S_ISLNK(mode))
        return EntryType::Symlink;
    return EntryType::Other;
}

/// RAII closer for the `DIR*` opened in `enumerate_at`. `fdopendir` takes
/// ownership of the fd handed to it, so from that call on the fd's lifetime
/// is tied to this, not to a `ScopedFd`.
struct DirCloser {
    DIR* dirp;
    explicit DirCloser(DIR* d) noexcept : dirp(d) {}
    ~DirCloser() {
        if (dirp != nullptr)
            ::closedir(dirp);
    }
    DirCloser(const DirCloser&) = delete;
    DirCloser& operator=(const DirCloser&) = delete;
};

} // namespace

std::optional<FileIdentity> capture_identity(int fd) {
    struct stat st {};
    if (::fstat(fd, &st) != 0)
        return std::nullopt;
    return FileIdentity{static_cast<std::uint64_t>(st.st_dev), static_cast<std::uint64_t>(st.st_ino)};
}

OpenRootResult open_root(const std::filesystem::path& path) {
    const int raw = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (raw < 0) {
        const int err = errno;
        spdlog::debug("confined_fs::open_root: refused '{}': {}", path.string(), std::strerror(err));
        return OpenRootResult{std::nullopt, Reason::RootInvalid, err};
    }
    ScopedFd fd{raw};
    const auto id = capture_identity(fd.get());
    if (!id) {
        const int err = errno;
        spdlog::debug("confined_fs::open_root: fstat failed for '{}': {}", path.string(),
                      std::strerror(err));
        return OpenRootResult{std::nullopt, Reason::RootInvalid, err};
    }
    return OpenRootResult{ConfinedRoot{std::move(fd), *id}, Reason::None, 0};
}

OpenDirResult open_dir_at(int parent_fd, const std::string& name, const FileIdentity& root_id) {
    if (is_invalid_name(name))
        return OpenDirResult{ScopedFd{}, Reason::InvalidName, 0};

    const int raw = ::openat(parent_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (raw < 0) {
        const int err = errno;
        if (err == ELOOP) {
            spdlog::warn("confined_fs::open_dir_at: symlink rejected for '{}'", name);
            return OpenDirResult{ScopedFd{}, Reason::SymlinkRejected, err};
        }
        if (err == ENOTDIR) {
            spdlog::debug("confined_fs::open_dir_at: not a directory: '{}'", name);
            return OpenDirResult{ScopedFd{}, Reason::NotRegularFile, err};
        }
        spdlog::debug("confined_fs::open_dir_at: openat('{}') failed: {}", name, std::strerror(err));
        return OpenDirResult{ScopedFd{}, Reason::OsError, err};
    }

    ScopedFd fd{raw};
    const auto id = capture_identity(fd.get());
    if (!id) {
        const int err = errno;
        return OpenDirResult{ScopedFd{}, Reason::OsError, err};
    }
    // Post-open fstat device re-verify -- the device check happens on the
    // FD we just opened, never on a path-based stat of `name`.
    if (id->dev != root_id.dev) {
        spdlog::warn("confined_fs::open_dir_at: device boundary crossed at '{}'", name);
        return OpenDirResult{ScopedFd{}, Reason::DeviceBoundary, 0};
    }
    return OpenDirResult{std::move(fd), Reason::None, 0};
}

EnumerateResult enumerate_at(int dir_fd, const FileIdentity& root_id, const EnumBudget& budget) {
    EnumerateResult result{};

    // INDEPENDENT-DESCRIPTION rule (PLAN-005/PLAN-012): obtain the
    // enumeration stream via a FRESH open-file-description over `dir_fd`'s
    // own inode, NEVER `dup(dir_fd)` -- a dup shares the same open-file-
    // description, including its directory read offset, so a second
    // enumeration of a reused root would silently resume (empty) from
    // wherever the first walk's readdir cursor stopped; dup() also does
    // not carry FD_CLOEXEC forward. `openat(dir_fd, ".")` resolves through
    // `dir_fd`'s own inode, not a path string, so it is exempt from the
    // no-path-below-root rule.
    const int raw = ::openat(dir_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (raw < 0) {
        result.reason = Reason::OsError;
        result.os_error = errno;
        return result;
    }
    ScopedFd owned{raw};
    DIR* dirp = ::fdopendir(owned.get());
    if (dirp == nullptr) {
        result.reason = Reason::OsError;
        result.os_error = errno;
        return result; // `owned` still closes `raw` on scope exit
    }
    [[maybe_unused]] const int released = owned.release(); // closedir() now owns the fd
    DirCloser closer{dirp};

    while (true) {
        if (std::chrono::steady_clock::now() >= budget.deadline) {
            result.reason = Reason::WallTimeCap;
            return result;
        }

        errno = 0;
        struct dirent* de = ::readdir(dirp);
        if (de == nullptr) {
            if (errno != 0) {
                result.reason = Reason::OsError;
                result.os_error = errno;
            }
            return result; // fully enumerated (reason stays None)
        }

        const std::string name = de->d_name;
        if (name == "." || name == "..")
            continue;

        if (static_cast<std::uint64_t>(result.entries.size()) >= budget.max_entries) {
            // Another entry exists beyond the budget: this is a real
            // truncation, not "happened to finish exactly at the cap".
            result.reason = Reason::EntryCap;
            return result;
        }

        DirEntry entry{};
        entry.name = name;
        struct stat st {};
        if (::fstatat(dir_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
            // PLAN-002: a stat failure is recorded as-is, never silently
            // reclassified as Other -- the walker reports Failed(OsError)
            // and never deletes it.
            entry.stat_error = errno;
        } else {
            const EntryType type = classify_mode(st.st_mode);
            const std::uint64_t size =
                (type == EntryType::RegularFile) ? static_cast<std::uint64_t>(st.st_size) : 0;
            entry.meta = EntryMeta{type, size, static_cast<std::uint64_t>(st.st_dev) == root_id.dev};
        }
        result.entries.push_back(std::move(entry));
    }
}

UnlinkOutcome unlink_at(int dir_fd, const std::string& name, UnlinkKind kind) {
    if (is_invalid_name(name))
        return UnlinkOutcome{EntryStatus::Failed, Reason::InvalidName, 0};

    // Accepted benign race (documented per spec): a symlink swapped in
    // between this entry's `fstatat` (in enumerate_at) and this `unlinkat`
    // can at worst cause `unlinkat` to remove the ATTACKER'S OWN symlink
    // entry inside this already-confined parent directory -- a name-level
    // operation against a name we were already about to act on. `unlinkat`
    // never traverses the symlink; it removes the directory entry by name.
    const int flags = (kind == UnlinkKind::EmptyDirectory) ? AT_REMOVEDIR : 0;
    if (::unlinkat(dir_fd, name.c_str(), flags) != 0) {
        const int err = errno;
        spdlog::debug("confined_fs::unlink_at: unlinkat('{}') failed: {}", name, std::strerror(err));
        return UnlinkOutcome{EntryStatus::Failed, Reason::OsError, err};
    }
    return UnlinkOutcome{EntryStatus::Deleted, Reason::None, 0};
}

namespace {

/// `Ops` adapter (confined_fs_walk.hpp) binding `walk_delete` to this TU's
/// primitives. Carries no policy of its own -- every branch here is a
/// direct pass-through to `open_dir_at`/`enumerate_at`/`unlink_at`.
struct PosixOps {
    using DirHandle = ScopedFd;

    FileIdentity root_id;

    OpenDirRes<DirHandle> open_dir(DirHandle& parent, const std::string& name) {
        OpenDirResult r = open_dir_at(parent.get(), name, root_id);
        if (r.reason != Reason::None)
            return OpenDirRes<DirHandle>{std::nullopt, r.reason, r.os_error};
        return OpenDirRes<DirHandle>{std::move(r.fd), Reason::None, 0};
    }

    EnumerateResult enumerate(DirHandle& dir, const EnumBudget& budget) {
        return enumerate_at(dir.get(), root_id, budget);
    }

    UnlinkOutcome unlink(DirHandle& parent, const std::string& name, UnlinkKind kind) {
        return unlink_at(parent.get(), name, kind);
    }

    std::chrono::steady_clock::time_point now() { return std::chrono::steady_clock::now(); }
};

} // namespace

DeleteResult delete_matching(const ConfinedRoot& root, const MatchFn& match,
                              const DeleteLimits& limits) {
    // The root frame handed to `walk_delete` must be an INDEPENDENT
    // open-file-description from `root.fd_` (same rule as enumerate_at
    // above), not the root's own fd moved out from under it -- `root` is
    // `const&` here specifically so a caller can run `delete_matching`
    // again on the SAME `ConfinedRoot` (root reuse, PLAN-005) after this
    // call returns.
    const int raw = ::openat(root.fd_.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (raw < 0) {
        DeleteResult result{};
        result.stop_reason = Reason::OsError;
        return result;
    }

    PosixOps ops{root.identity()};
    return walk_delete<PosixOps>(ScopedFd{raw}, ops, match, limits);
}

} // namespace yuzu::agent::confined_fs

#endif // !_WIN32
