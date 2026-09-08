/**
 * autoruns_macos.cpp — macOS leg (P14) of the autoruns plugin's `collect_*`
 * trio (autoruns_legs.hpp).
 *
 * Sources covered (all eight macOS SourceIds, autoruns_catalog.hpp):
 *   - /Library/{LaunchDaemons,LaunchAgents}                (system)
 *   - /System/Library/{LaunchDaemons,LaunchAgents}         (system, apple_system by path)
 *   - /Users/(each real home)/Library/LaunchAgents         (user, per real home directory)
 *   - Login Items                                          (mac_login_items — always CONSTRAINED,
 *                                                            no public read API; see below)
 *   - /etc/periodic/{daily,weekly,monthly} scripts         (mac_periodic)
 *   - /etc/emond.d/rules/ plists                           (mac_emond)
 *
 * File truth only, rung 1: no launchctl, no osascript, no sfltool — zero
 * process spawns anywhere in this leg. This is a DELIBERATE divergence from
 * a services-style plugin that reads `launchctl print-disabled` overrides:
 * a plist's own `Disabled` key is read, but launchctl's separate override
 * database (which can re-enable a Disabled=true job, or vice versa) is not
 * consulted — this leg reports the file's own claim, not launchd's live
 * runtime state.
 *
 * Login Items has no file this leg can read at all: the list lives in a
 * private per-user BTM (Background Task Management) database with no
 * public API (autoruns_catalog.hpp's own documented CONSTRAINED rationale —
 * the only route is osascript driving System Events, a rung-3 governed-shell
 * acquisition this leg does not perform). So `mac_login_items` always emits
 * the same constrained status line and zero rows, never a real read attempt.
 *
 * The CFPropertyListCreateWithData plist read itself is header-only
 * (autoruns_macos.hpp's `plist_to_launchd_fields`) so the test binary can
 * exercise it directly against real captured fixtures; this TU does the
 * directory walk and hands each file's bytes to that header function (for
 * launchd plists) or to this TU's own local emond-rule extraction (below —
 * emond's row shape, EmondRuleFields, is not launchd's, so it is not routed
 * through plist_to_launchd_fields, though it uses the same
 * CFPropertyListCreateWithData primitive).
 */
#ifdef __APPLE__

#include "autoruns_catalog.hpp"
#include "autoruns_macos.hpp"
#include "autoruns_parsers.hpp"

#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/plugin.hpp>

#include <CoreFoundation/CoreFoundation.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::autoruns {

namespace {

constexpr std::size_t kMaxEntriesPerDir = 4096;
constexpr std::size_t kMaxPlistBytes = 1024 * 1024; // 1 MiB, same cap as P13's read_file_bounded

/// Move-only RAII owner for a POSIX DIR*; closes exactly once, including on
/// an early return mid-walk.
class DirHandle {
public:
    explicit DirHandle(DIR* d) noexcept : dir_(d) {}
    ~DirHandle() {
        if (dir_ != nullptr) closedir(dir_);
    }
    DirHandle(const DirHandle&) = delete;
    DirHandle& operator=(const DirHandle&) = delete;
    [[nodiscard]] DIR* get() const noexcept { return dir_; }
    [[nodiscard]] bool valid() const noexcept { return dir_ != nullptr; }

private:
    DIR* dir_;
};

/// Move-only RAII owner for a POSIX fd; closes exactly once. Not used for a
/// fd handed to fdopendir() — DirHandle owns that one once fdopendir
/// succeeds (closedir() closes the underlying fd too; double-closing it here
/// as well would be a double-close bug, not a safety net).
class FdHandle {
public:
    explicit FdHandle(int fd) noexcept : fd_(fd) {}
    ~FdHandle() {
        if (fd_ >= 0) close(fd_);
    }
    FdHandle(const FdHandle&) = delete;
    FdHandle& operator=(const FdHandle&) = delete;
    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

private:
    int fd_;
};

/// Outcome of an O_NOFOLLOW directory open: the handle (invalid on any
/// failure), plus whether that failure is a real constraint (permission
/// denied, a refused symlink, a path component that wasn't a directory —
/// anything but a genuinely-absent path) and, if so, a reason token for the
/// `constrained` status line. `reason` is empty whenever `constrained` is
/// false, whether the open succeeded or the path was simply absent.
struct DirOpenOutcome {
    DirHandle handle;
    bool constrained = false;
    std::string_view reason{};
};

/// `errno` -> a stable reason token for a `constrained` source status.
std::string_view dir_open_constraint_token(int err) noexcept {
    switch (err) {
        case EACCES: return "permission_denied";
        case ELOOP: return "symlink_refused";
        case ENOTDIR: return "not_a_directory";
        default: return "dir_open_failed";
    }
}

/// Classifies an already-attempted `open`/`openat` result (`fd`, with
/// `errno` still current from that call if `fd < 0`) into a DirOpenOutcome,
/// completing the open via `fdopendir()` on success. A genuinely-absent
/// directory (ENOENT) is reported as a plain invalid handle with
/// `constrained=false` — several of this leg's paths are legitimately
/// absent on a given host (emond is removed on every captured host; a fresh
/// install may have no /Library/LaunchDaemons entries at all), and "absent"
/// is not this leg's error to report. Any OTHER open failure (permission
/// denied, a refused symlink, a non-directory component) is a real
/// constraint the caller must surface, never silently folded into "zero
/// rows" (autoruns' AC4: failure != empty).
DirOpenOutcome dir_open_outcome_from_fd(int fd) {
    if (fd < 0) {
        const int err = errno;
        if (is_benign_absent_errno(err)) return DirOpenOutcome{DirHandle{nullptr}, false, {}};
        return DirOpenOutcome{DirHandle{nullptr}, true, dir_open_constraint_token(err)};
    }
    DIR* d = fdopendir(fd);
    if (d == nullptr) {
        const int err = errno;
        close(fd);
        if (is_benign_absent_errno(err)) return DirOpenOutcome{DirHandle{nullptr}, false, {}};
        return DirOpenOutcome{DirHandle{nullptr}, true, dir_open_constraint_token(err)};
    }
    return DirOpenOutcome{DirHandle{d}, false, {}};
}

/// Opens `path` refusing to follow a symlink at that exact component
/// (O_NOFOLLOW). See dir_open_outcome_from_fd for the absence-vs-constraint
/// contract.
DirOpenOutcome open_dir_no_follow_checked(const std::string& path) {
    return dir_open_outcome_from_fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW));
}

/// Same contract as open_dir_no_follow_checked, but resolves exactly one
/// path COMPONENT (`name`) via `openat(parent_fd, ...)` rather than a fresh
/// `open()` on a joined path string. This is the primitive
/// collect_user_launchagents needs to stay confined to a caller-verified
/// home directory: opening "home/Library/LaunchAgents" as one string lets
/// the kernel resolve the intermediate "Library" component through normal
/// (symlink-following) path resolution, even though the leaf itself is
/// O_NOFOLLOW-checked — a user-owned symlink swapped in for "Library" would
/// escape confinement. Chaining this hop-by-hop from an already-opened
/// parent fd (mirroring agents/core/src/confined_fs_posix.cpp's
/// `open_dir_at`) makes every component's own O_NOFOLLOW check independent
/// of how the previous one resolved.
DirOpenOutcome open_dir_no_follow_at_checked(int parent_fd, const char* name) {
    return dir_open_outcome_from_fd(openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW));
}

bool ends_with(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

/// `sources=` is a comma-separated SourceId allow-list; empty means every
/// source runs (the common, unfiltered `list` case this plugin's dispatcher
/// test exercises).
bool source_in_filter(std::string_view filter, SourceId id) noexcept {
    if (filter.empty()) return true;
    const std::string_view name = source_id_string(id);
    std::size_t pos = 0;
    while (pos <= filter.size()) {
        const std::size_t comma = filter.find(',', pos);
        const std::string_view tok =
            comma == std::string_view::npos ? filter.substr(pos) : filter.substr(pos, comma - pos);
        if (tok == name) return true;
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return false;
}

void emit_status(yuzu::CommandContext& ctx, SourceId id, YuzuSupportLevel support,
                 std::optional<std::size_t> rows, std::string_view reason) {
    ctx.write_output(format_source_status(id, support, rows, reason));
}

/// Reads `name` inside the directory backing `dir_fd`, refusing a symlink
/// (O_NOFOLLOW) at the leaf itself, capped at kMaxPlistBytes. Returns false
/// on any open/fstat/read failure or on a rejected symlink — this is a
/// best-effort collector: a file it cannot read contributes nothing rather
/// than aborting the whole directory's walk.
bool read_file_bounded(int dir_fd, const char* name, std::vector<uint8_t>& out,
                       std::int64_t& mtime) {
    FdHandle fd(openat(dir_fd, name, O_RDONLY | O_NOFOLLOW));
    if (!fd.valid()) return false;
    struct stat st{};
    if (fstat(fd.get(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
    mtime = static_cast<std::int64_t>(st.st_mtime);
    const std::size_t want = static_cast<std::size_t>(st.st_size) > kMaxPlistBytes
                                 ? kMaxPlistBytes
                                 : static_cast<std::size_t>(st.st_size);
    out.resize(want);
    std::size_t total = 0;
    while (total < want) {
        const ssize_t n = read(fd.get(), out.data() + total, want - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) break;
        total += static_cast<std::size_t>(n);
    }
    out.resize(total);
    return true;
}

/// Enumerates `*.plist` entries in an already-opened directory (no
/// recursion), capped at kMaxEntriesPerDir, and hands each one's bytes +
/// mtime to `on_plist`. An invalid handle (directory absent, or a
/// component along the way was refused) silently contributes zero rows —
/// the same "absence is not an error" contract every rung-1 leg in this
/// codebase follows.
template <typename OnPlist>
void walk_plist_dir_handle(const DirHandle& dir, OnPlist&& on_plist) {
    if (!dir.valid()) return;
    const int dfd = dirfd(dir.get());
    std::size_t seen = 0;
    struct dirent* entry = nullptr;
    while (seen < kMaxEntriesPerDir && (entry = readdir(dir.get())) != nullptr) {
        ++seen;
        const std::string_view name(entry->d_name);
        if (name == "." || name == "..") continue;
        if (!ends_with(name, ".plist")) continue;
        std::vector<uint8_t> bytes;
        std::int64_t mtime = 0;
        if (!read_file_bounded(dfd, entry->d_name, bytes, mtime)) continue;
        on_plist(entry->d_name, bytes, mtime);
    }
}

/// Enumerates `*.plist` entries directly under `dir_path` (no recursion) by
/// opening the whole path in one shot — safe ONLY when `dir_path` is a
/// single trusted component below a root the OS already protects (e.g.
/// `/Library/LaunchDaemons`), never below a path segment an unprivileged
/// user controls (see open_dir_no_follow_at_checked's banner and
/// collect_user_launchagents, which does NOT use this).
/// Whether a directory-level walk hit a real constraint opening its root
/// (vs. a genuine absence) — deliberately holds no DirHandle so it's a
/// plain, trivially-returned value type.
struct DirConstraint {
    bool constrained = false;
    std::string_view reason{};
};

/// Same enumeration as above, plus the directory-open outcome so the caller
/// can distinguish "genuinely absent" from a real constraint (AC4).
template <typename OnPlist>
DirConstraint walk_plist_dir(const std::string& dir_path, OnPlist&& on_plist) {
    DirOpenOutcome open = open_dir_no_follow_checked(dir_path);
    walk_plist_dir_handle(open.handle, std::forward<OnPlist>(on_plist));
    return DirConstraint{open.constrained, open.reason};
}

/// Enumerates every non-directory entry (regular file or symlink — periodic
/// scripts are sometimes one, e.g. a Homebrew formula symlinking into
/// /etc/periodic/daily) directly under `dir_path`, capped at
/// kMaxEntriesPerDir, handing each name + its own (non-dereferenced) mtime
/// to `on_entry`. No content is read here — periodic scripts carry no
/// structured metadata this plugin decodes, only their existence and mtime.
template <typename OnEntry>
DirConstraint walk_dir_names(const std::string& dir_path, OnEntry&& on_entry) {
    DirOpenOutcome open = open_dir_no_follow_checked(dir_path);
    if (!open.handle.valid()) return DirConstraint{open.constrained, open.reason};
    const int dfd = dirfd(open.handle.get());
    std::size_t seen = 0;
    struct dirent* entry = nullptr;
    while (seen < kMaxEntriesPerDir && (entry = readdir(open.handle.get())) != nullptr) {
        ++seen;
        const std::string_view name(entry->d_name);
        if (name == "." || name == "..") continue;
        struct stat st{};
        if (fstatat(dfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) continue;
        on_entry(entry->d_name, static_cast<std::int64_t>(st.st_mtime));
    }
    return DirConstraint{};
}

/// Local CF plist parse for emond rules: identical primitive to
/// autoruns_macos.hpp's plist_to_launchd_fields (CFDataCreate ->
/// CFPropertyListCreateWithData), but returning the raw root object rather
/// than a LaunchdFields — an emond rule file's root is documented as an
/// ARRAY of rule dictionaries, a shape plist_to_launchd_fields deliberately
/// rejects (it requires a top-level dictionary, launchd's own plist shape).
/// Not exposed in the header: no real-capture emond fixture exists (emond
/// is removed on every host these fixtures were captured from — see
/// test_autoruns_parsers.cpp's own emond test banner), so there is nothing
/// for a test to call this against yet.
bool parse_plist_root(const std::vector<uint8_t>& bytes,
                      yuzu::agent::ScopedCFRef<CFPropertyListRef>& out) {
    yuzu::agent::ScopedCFRef<CFDataRef> data(
        CFDataCreate(kCFAllocatorDefault, bytes.data(), static_cast<CFIndex>(bytes.size())));
    if (!data) return false;
    CFErrorRef raw_error = nullptr;
    out = yuzu::agent::ScopedCFRef<CFPropertyListRef>(CFPropertyListCreateWithData(
        kCFAllocatorDefault, data.get(), kCFPropertyListImmutable, nullptr, &raw_error));
    yuzu::agent::ScopedCFRef<CFErrorRef> error(raw_error);
    return static_cast<bool>(out);
}

/// Extracts the fields parse_emond_rule_plist_fields (autoruns_parsers.hpp)
/// needs from one rule dictionary. emond's rule schema is not documented by
/// Apple beyond example rules shipped historically in /etc/emond.d/rules —
/// `name`/`enabled` are read at the rule's top level and a nested
/// `startcommand` dict's `command` string, matching the shape of Apple's own
/// sample rules; any field absent or in an unexpected CF type is left at
/// EmondRuleFields' own default, never a crash.
EmondRuleFields emond_fields_from_dict(CFDictionaryRef dict) {
    EmondRuleFields fields;
    if (auto name = detail::dict_get_string(dict, CFSTR("name"))) fields.name = *name;
    if (auto enabled = detail::dict_get_bool(dict, CFSTR("enabled"))) {
        fields.enabled_present = true;
        fields.enabled_value = *enabled;
    }
    const void* v = nullptr;
    if (CFDictionaryGetValueIfPresent(dict, CFSTR("startcommand"), &v)) {
        const auto ref = static_cast<CFTypeRef>(v);
        if (ref != nullptr && CFGetTypeID(ref) == CFDictionaryGetTypeID()) {
            const auto start_dict = static_cast<CFDictionaryRef>(ref);
            if (auto cmd = detail::dict_get_string(start_dict, CFSTR("command"))) fields.command = *cmd;
        }
    }
    return fields;
}

/// Emits one `autorun|` row per successfully-parsed `*.plist` under
/// `dir_path`, all attributed to `source_id`/`scope`; a plist this host's CF
/// implementation cannot parse contributes nothing (never a fabricated
/// row — PlistError is silently skipped here because the row-level contract
/// this plugin's schema offers has no per-row error field, only a per-source
/// row count; the header's own test exercises the typed-error path
/// directly). Returns the number of rows emitted.
std::size_t collect_launchd_dir_handle(yuzu::CommandContext& ctx, SourceId source_id,
                                       const DirHandle& dir, const std::string& location,
                                       Scope scope, std::string_view user_override) {
    std::size_t count = 0;
    walk_plist_dir_handle(dir, [&](const char* name, const std::vector<uint8_t>& bytes,
                                   std::int64_t mtime) {
        auto parsed = plist_to_launchd_fields(std::span<const uint8_t>{bytes.data(), bytes.size()});
        if (!parsed) return;
        Row row = launchd_row_from_fields(source_id, *parsed, location + "/" + name, scope, mtime);
        if (!user_override.empty()) row.user = std::string{user_override};
        ctx.write_output(format_row(row));
        ++count;
    });
    return count;
}

/// A whole `collect_*` call's outcome: rows emitted, plus whether ANY
/// directory it opened along the way hit a real constraint rather than a
/// genuine absence (AC4) — `note_dir_constraint` accumulates every distinct
/// token seen (a per-user walk can hit the same token, e.g.
/// `permission_denied`, on several different users' homes; it is recorded
/// once, not once per user).
struct DirCollectOutcome {
    std::size_t rows = 0;
    bool constrained = false;
    std::string reason{};
};

void note_dir_constraint(DirCollectOutcome& outcome, std::string_view token) {
    outcome.constrained = true;
    if (outcome.reason.find(token) != std::string::npos) return; // already recorded
    if (!outcome.reason.empty()) outcome.reason += ',';
    outcome.reason.append(token);
}

DirCollectOutcome collect_launchd_dir(yuzu::CommandContext& ctx, SourceId source_id,
                                      const std::string& dir_path, Scope scope,
                                      std::string_view user_override) {
    DirOpenOutcome open = open_dir_no_follow_checked(dir_path);
    DirCollectOutcome outcome;
    outcome.rows = collect_launchd_dir_handle(ctx, source_id, open.handle, dir_path, scope, user_override);
    if (open.constrained) note_dir_constraint(outcome, open.reason);
    return outcome;
}

/// /Users/*/Library/LaunchAgents — one real per-user home per iteration.
/// "Real" is judged by st_uid on the home directory itself (>= 500):
/// non-account entries under /Users (`Shared`, a stray dotfile) are owned by
/// root or otherwise fall below every macOS-assigned real-account uid, so
/// this threshold excludes them without hardcoding names that vary by
/// install. The username reported in each row is the directory's own name
/// (the mac_user_launchagents scope's documented identity), not a
/// getpwuid() lookup — this leg reads files, it does not call into Open
/// Directory.
DirCollectOutcome collect_user_launchagents(yuzu::CommandContext& ctx) {
    DirCollectOutcome outcome;
    constexpr const char* kUsersDir = "/Users";
    DirOpenOutcome users_open = open_dir_no_follow_checked(kUsersDir);
    if (users_open.constrained) note_dir_constraint(outcome, users_open.reason);
    if (!users_open.handle.valid()) return outcome;
    std::size_t seen = 0;
    struct dirent* entry = nullptr;
    while (seen < kMaxEntriesPerDir && (entry = readdir(users_open.handle.get())) != nullptr) {
        ++seen;
        const std::string_view name(entry->d_name);
        if (name == "." || name == "..") continue;
        const std::string home = std::string{kUsersDir} + "/" + entry->d_name;
        // O_NOFOLLOW on the home directory itself: a symlinked "user" entry
        // under /Users is not a real per-user home this leg will read into.
        const int home_fd = open(home.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (home_fd < 0) {
            const int err = errno;
            if (!is_benign_absent_errno(err)) note_dir_constraint(outcome, dir_open_constraint_token(err));
            continue;
        }
        FdHandle home_handle(home_fd);
        struct stat st{};
        if (fstat(home_handle.get(), &st) != 0) continue;
        if (st.st_uid < 500) continue; // system/shared account, not a real user home
        // Walk "Library" then "LaunchAgents" as two openat() hops chained
        // from home_fd, each independently O_NOFOLLOW-checked — a single
        // open() on the joined "home/Library/LaunchAgents" string would let
        // the kernel resolve the intermediate "Library" component through
        // normal symlink-following path resolution, escaping confinement to
        // this user's own home (see open_dir_no_follow_at_checked's banner).
        DirOpenOutcome library_open = open_dir_no_follow_at_checked(home_handle.get(), "Library");
        if (library_open.constrained) note_dir_constraint(outcome, library_open.reason);
        if (!library_open.handle.valid()) continue;
        DirOpenOutcome agents_open =
            open_dir_no_follow_at_checked(dirfd(library_open.handle.get()), "LaunchAgents");
        if (agents_open.constrained) note_dir_constraint(outcome, agents_open.reason);
        if (!agents_open.handle.valid()) continue;
        outcome.rows += collect_launchd_dir_handle(ctx, SourceId::mac_user_launchagents, agents_open.handle,
                                                   home + "/Library/LaunchAgents", Scope::user, name);
    }
    return outcome;
}

} // namespace

int collect_macos(yuzu::CommandContext& ctx, std::string_view filter) {
    struct SystemDirSpec {
        SourceId id;
        const char* path;
    };
    static constexpr SystemDirSpec kSystemDirs[] = {
        {SourceId::mac_launchdaemons, "/Library/LaunchDaemons"},
        {SourceId::mac_launchagents, "/Library/LaunchAgents"},
        {SourceId::mac_system_launchdaemons, "/System/Library/LaunchDaemons"},
        {SourceId::mac_system_launchagents, "/System/Library/LaunchAgents"},
    };

    for (const auto& spec : kSystemDirs) {
        if (!source_in_filter(filter, spec.id)) {
            emit_status(ctx, spec.id, YUZU_SUPPORT_SUPPORTED, std::nullopt, "filtered");
            continue;
        }
        const auto outcome = collect_launchd_dir(ctx, spec.id, spec.path, Scope::system, {});
        if (outcome.constrained) {
            emit_status(ctx, spec.id, YUZU_SUPPORT_CONSTRAINED, outcome.rows, outcome.reason);
        } else {
            emit_status(ctx, spec.id, YUZU_SUPPORT_SUPPORTED, outcome.rows, "launchd_plist_walk");
        }
    }

    if (!source_in_filter(filter, SourceId::mac_user_launchagents)) {
        emit_status(ctx, SourceId::mac_user_launchagents, YUZU_SUPPORT_SUPPORTED, std::nullopt,
                   "filtered");
    } else {
        const auto outcome = collect_user_launchagents(ctx);
        if (outcome.constrained) {
            emit_status(ctx, SourceId::mac_user_launchagents, YUZU_SUPPORT_CONSTRAINED, outcome.rows,
                       outcome.reason);
        } else {
            emit_status(ctx, SourceId::mac_user_launchagents, YUZU_SUPPORT_SUPPORTED, outcome.rows,
                       "launchd_plist_walk");
        }
    }

    // Login Items: no file this leg can read, ever — always this exact
    // status line, unaffected by `sources=` (there is no real read to skip).
    emit_status(ctx, SourceId::mac_login_items, YUZU_SUPPORT_CONSTRAINED, std::size_t{0},
               "btm_private_database_no_public_api");

    if (!source_in_filter(filter, SourceId::mac_periodic)) {
        emit_status(ctx, SourceId::mac_periodic, YUZU_SUPPORT_SUPPORTED, std::nullopt, "filtered");
    } else {
        std::size_t count = 0;
        DirCollectOutcome outcome;
        for (const char* sub : {"daily", "weekly", "monthly"}) {
            const std::string dir_path = std::string{"/etc/periodic/"} + sub;
            const DirConstraint dir_outcome =
                walk_dir_names(dir_path, [&](const char* name, std::int64_t mtime) {
                    Row row;
                    row.source_id = SourceId::mac_periodic;
                    row.catalog_version = kAutorunSourceCatalogVersion;
                    row.location = dir_path;
                    row.entry = name;
                    row.target = dir_path + "/" + name;
                    // periodic(8) executes every script found here unconditionally
                    // -- there is no separate enable/disable flag, so presence
                    // itself is the documented default: Enabled::enabled, not
                    // `unknown` (reserved for a source with no default to reason
                    // from at all).
                    row.enabled = Enabled::enabled;
                    row.scope = Scope::system;
                    row.user = "-";
                    row.signed_state = signed_from_path(row.target);
                    row.mtime = mtime;
                    ctx.write_output(format_row(row));
                    ++count;
                });
            if (dir_outcome.constrained) note_dir_constraint(outcome, dir_outcome.reason);
        }
        if (outcome.constrained) {
            emit_status(ctx, SourceId::mac_periodic, YUZU_SUPPORT_CONSTRAINED, count, outcome.reason);
        } else {
            emit_status(ctx, SourceId::mac_periodic, YUZU_SUPPORT_SUPPORTED, count, "periodic_dir_walk");
        }
    }

    if (!source_in_filter(filter, SourceId::mac_emond)) {
        emit_status(ctx, SourceId::mac_emond, YUZU_SUPPORT_SUPPORTED, std::nullopt, "filtered");
    } else {
        std::size_t count = 0;
        const std::string dir_path = "/etc/emond.d/rules";
        const DirConstraint outcome =
            walk_plist_dir(dir_path, [&](const char* name, const std::vector<uint8_t>& bytes,
                                         std::int64_t mtime) {
                const std::string full_path = dir_path + "/" + name;
                yuzu::agent::ScopedCFRef<CFPropertyListRef> root;
                if (!parse_plist_root(bytes, root)) return;

                std::vector<CFDictionaryRef> rule_dicts;
                const CFTypeID type = CFGetTypeID(root.get());
                if (type == CFArrayGetTypeID()) {
                    const auto arr = static_cast<CFArrayRef>(root.get());
                    const CFIndex n = CFArrayGetCount(arr);
                    for (CFIndex i = 0; i < n; ++i) {
                        const auto elem_ref = static_cast<CFTypeRef>(CFArrayGetValueAtIndex(arr, i));
                        if (elem_ref != nullptr && CFGetTypeID(elem_ref) == CFDictionaryGetTypeID())
                            rule_dicts.push_back(static_cast<CFDictionaryRef>(elem_ref));
                    }
                } else if (type == CFDictionaryGetTypeID()) {
                    rule_dicts.push_back(static_cast<CFDictionaryRef>(root.get()));
                }

                for (CFDictionaryRef rule_dict : rule_dicts) {
                    const Row row = parse_emond_rule_plist_fields(emond_fields_from_dict(rule_dict),
                                                                  full_path, mtime);
                    ctx.write_output(format_row(row));
                    ++count;
                }
            });
        if (outcome.constrained) {
            emit_status(ctx, SourceId::mac_emond, YUZU_SUPPORT_CONSTRAINED, count, outcome.reason);
        } else {
            emit_status(ctx, SourceId::mac_emond, YUZU_SUPPORT_SUPPORTED, count, "emond_rule_plist_walk");
        }
    }

    return 0; // a degraded per-source read is reported via source| lines, not this rc
}

} // namespace yuzu::autoruns

#endif // __APPLE__
