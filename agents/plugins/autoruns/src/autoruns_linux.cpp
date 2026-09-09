/**
 * autoruns_linux.cpp — Linux leg of the autoruns plugin (`collect_linux`).
 *
 * Sources covered (autoruns_catalog.hpp): /etc/crontab, /etc/cron.d entries,
 * /etc/cron.{hourly,daily,weekly,monthly} entries, per-user crontabs
 * (/var/spool/cron/crontabs and /var/spool/cron entries), /etc/anacrontab,
 * /var/spool/at entries (at(1) jobs), systemd system/user timer units (+
 * timers.target.wants / WantedBy=.wants symlink enablement, with a rung-2
 * `systemctl list-timers` argv fallback), XDG autostart (system + per-user),
 * /etc/rc.local, and /etc/init.d entries (listing only, CONSTRAINED).
 *
 * Every acquisition here is a bounded local file read or directory listing
 * (`read_file_bounded`, defined in this TU) EXCEPT the one declared
 * exception: `autoruns/collect_linux#1` (docs/wave7/integration-autoruns-
 * linux.md), a `systemctl list-timers` argv call used only when zero of the
 * three system systemd unit directories could be enumerated. No other spawn
 * exists in this TU.
 *
 * `read_file_bounded` never resolves a symlink for reading (O_NOFOLLOW on
 * the leaf) and never returns an empty success for a failed acquisition --
 * every failure is a typed `ReadError` a caller classifies into the
 * catalog's supported/constrained/unsupported vocabulary
 * (`classify_read_error`).
 *
 * Per-user scans (systemd --user timers, XDG user autostart) report the
 * owning uid NUMERICALLY (`owner_uid_string`, a bare `stat`) rather than via
 * `getpwuid_r` -- the NSS/directory-service lookup that call can trigger has
 * no bound on this plugin's read-only, no-network contract, and a hung
 * lookup would stall the whole leg (the same "no libc directory-lookup
 * deadline hazard" precedent noted elsewhere in this codebase for uid/gid
 * resolution off a hot path).
 */
#ifdef __linux__

#include "autoruns_legs.hpp"

#include <posix_dir_walk.hpp>
#include <yuzu/agent/runner_status.hpp>
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <expected>
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>
#include <utility>
#include <vector>

namespace yuzu::autoruns {

namespace {

constexpr std::size_t kDefaultMaxReadBytes = 1'048'576; // 1 MiB
constexpr std::size_t kMaxDirEntries = 4096;            // defensive cap per directory scan

// ── errno / bounded-read plumbing ────────────────────────────────────────

std::string errno_token_for(int e) {
    switch (e) {
    case EACCES:       return "EACCES";
    case EPERM:        return "EPERM";
    case ELOOP:        return "ELOOP";
    case ENOENT:       return "ENOENT";
    case ENOTDIR:      return "ENOTDIR";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    default:           return "ERRNO_" + std::to_string(e);
    }
}

/// Accumulates a per-entry constraint reason with a dedup contract matching
/// autoruns_macos.cpp's note_dir_constraint: a token repeating identically
/// across many entries/profiles in one scan collapses to a single mention
/// rather than growing the reason string once per occurrence (a directory
/// or per-user timer scan spanning many entries/profiles could otherwise
/// produce an unbounded, mostly-duplicate reason string).
void note_file_constraint(bool& any_constrained, std::string& reason, std::string_view token) {
    any_constrained = true;
    if (reason.find(token) != std::string::npos) return;
    if (!reason.empty()) reason += ',';
    reason += token;
}

/// Lower-cases an errno_token_for() result so every reason in this schema
/// stays lower_snake_case for a downstream string-matching consumer,
/// matching permission_denied / symlink_refused / oversized / not_regular /
/// absent above -- shared by classify_read_error and list_dir's own
/// unclassified-opendir-failure fallback, which used to skip this step.
std::string lowercase_errno_token(std::string_view token) {
    std::string out{token};
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

struct ReadError {
    std::string errno_token;
};

/// Bounded, symlink-refusing, single-file read: O_NOFOLLOW on the leaf means
/// a symlink there is refused at open() with ELOOP, never silently
/// resolved. fstat's S_ISREG check additionally refuses a non-regular leaf
/// (fifo/device/socket) that O_NOFOLLOW alone would not catch. Never
/// returns an empty success for a failed acquisition -- every failure path
/// below is a std::unexpected.
std::expected<std::string, ReadError> read_file_bounded(const std::string& path,
                                                         std::size_t max_bytes = kDefaultMaxReadBytes) {
    int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected(ReadError{errno_token_for(errno)});
    }
    struct FdGuard {
        int fd;
        ~FdGuard() {
            if (fd >= 0) ::close(fd);
        }
    } guard{fd};

    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        return std::unexpected(ReadError{errno_token_for(errno)});
    }
    if (!S_ISREG(st.st_mode)) {
        return std::unexpected(ReadError{"NOT_REGULAR"});
    }
    if (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) > static_cast<std::uint64_t>(max_bytes)) {
        return std::unexpected(ReadError{"OVERSIZED"});
    }

    std::string buf(static_cast<std::size_t>(st.st_size), '\0');
    std::size_t total = 0;
    while (total < buf.size()) {
        ssize_t n = ::read(fd, buf.data() + total, buf.size() - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return std::unexpected(ReadError{errno_token_for(errno)});
        }
        if (n == 0) break; // file shrank under us -- return what was captured
        total += static_cast<std::size_t>(n);
    }
    buf.resize(total);
    return buf;
}

std::int64_t mtime_of(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return 0;
    return static_cast<std::int64_t>(st.st_mtime);
}

/// (support, reason) for a failed read_file_bounded -- `required_by_catalog`
/// distinguishes a file this catalog treats as a standing system fixture
/// (/etc/crontab, /etc/anacrontab: ENOENT there is a genuine constraint) from
/// an optional one (most everything else: ENOENT just means the mechanism
/// isn't configured on this host, which is SUPPORTED with zero rows, not a
/// limitation).
struct FileStatus {
    YuzuSupportLevel support;
    std::string reason;
};

FileStatus classify_read_error(const ReadError& err, bool required_by_catalog) {
    if (err.errno_token == "EACCES" || err.errno_token == "EPERM")
        return {YUZU_SUPPORT_CONSTRAINED, "permission_denied"};
    if (err.errno_token == "ELOOP")
        return {YUZU_SUPPORT_CONSTRAINED, "symlink_refused"};
    if (err.errno_token == "OVERSIZED")
        return {YUZU_SUPPORT_CONSTRAINED, "oversized"};
    if (err.errno_token == "NOT_REGULAR")
        return {YUZU_SUPPORT_CONSTRAINED, "not_regular"};
    if (err.errno_token == "ENOENT")
        return required_by_catalog ? FileStatus{YUZU_SUPPORT_CONSTRAINED, "absent"}
                                    : FileStatus{YUZU_SUPPORT_SUPPORTED, "absent"};
    // Fallback: any other errno token (e.g. "ENOTDIR", "ERRNO_13").
    return {YUZU_SUPPORT_CONSTRAINED, lowercase_errno_token(err.errno_token)};
}

// ── directory listing ────────────────────────────────────────────────────

struct DirListing {
    std::vector<std::string> names; // capped at kMaxDirEntries, "." / ".." excluded
    bool opened = false;
    bool absent = false;
    bool permission_denied = false;
    std::string other_token; // non-empty for any other opendir() failure
    bool truncated = false;  // cap hit AND a real entry remained unread (AC4: a
                             // capped listing is not a complete one)
};

DirListing list_dir(const std::string& path, std::size_t cap = kMaxDirEntries) {
    DirListing out;
    DIR* d = ::opendir(path.c_str());
    if (!d) {
        int e = errno;
        if (e == ENOENT) out.absent = true;
        else if (e == EACCES || e == EPERM) out.permission_denied = true;
        else out.other_token = lowercase_errno_token(errno_token_for(e));
        return out;
    }
    out.opened = true;
    struct DirGuard {
        DIR* d;
        ~DirGuard() {
            if (d) ::closedir(d);
        }
    } guard{d};
    const auto walk = yuzu::shared::walk_dir_capped(d, cap, [&](const struct dirent* ent) {
        out.names.emplace_back(std::string_view{ent->d_name});
        return true;
    });
    // A real I/O error (mid-scan or at the cap-boundary lookahead) is folded
    // into the SAME `truncated` signal every caller already escalates to
    // Constrained on -- a partial listing from either cause must never be
    // reported as a complete Supported result.
    out.truncated = walk.truncated || walk.enumeration_error;
    return out;
}

/// run-parts(8) naming rule: a name containing '.' or '~' is skipped by
/// run-parts itself (backup/package-manager artefact convention), so it
/// never actually executes -- applied here to /etc/cron.d and the
/// /etc/cron.{hourly,daily,weekly,monthly} directories alike, since both are
/// genuinely driven by run-parts on a real system.
bool run_parts_valid_name(std::string_view name) {
    return name.find('.') == std::string_view::npos && name.find('~') == std::string_view::npos;
}

std::string owner_uid_string(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return "-";
    return std::to_string(static_cast<unsigned long>(st.st_uid));
}

// ── sources= allow-list filter (leg-internal; autoruns_plugin.cpp:do_list) ─

bool source_wanted(std::string_view filter, SourceId id) {
    if (filter.empty()) return true;
    const std::string_view name = source_id_string(id);
    std::size_t pos = 0;
    while (pos <= filter.size()) {
        std::size_t comma = filter.find(',', pos);
        std::string_view tok =
            comma == std::string_view::npos ? filter.substr(pos) : filter.substr(pos, comma - pos);
        if (tok == name) return true;
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return false;
}

// ── systemd wants-symlink enablement ─────────────────────────────────────

struct WantsListing {
    std::string text; // "<name>[ -> <target>]\n" per entry -- see autoruns_parsers.hpp:timer_enabled_from_wants
    bool opened = false;
    bool enumeration_error = false; // a real readdir() I/O error stopped the scan
                                    // early (mid-scan OR at the cap-boundary
                                    // lookahead) -- the listing is genuinely
                                    // incomplete, distinct from "opened fine,
                                    // nothing here"; a caller must not treat
                                    // `opened && no match found` as a confident
                                    // Enabled::disabled when this is set.
    bool truncated = false; // cap hit AND a real entry remained unread -- matches
                            // the sibling DirListing type's field; a capped scan
                            // with no match found is NOT proof the timer isn't
                            // enabled (the matching symlink could be past the
                            // cap), same reasoning as enumeration_error above.
};

WantsListing build_wants_listing(const std::string& wants_dir) {
    WantsListing out;
    DIR* d = ::opendir(wants_dir.c_str());
    if (!d) return out;
    out.opened = true;
    struct DirGuard {
        DIR* d;
        ~DirGuard() {
            if (d) ::closedir(d);
        }
    } guard{d};
    const auto walk = yuzu::shared::walk_dir_capped(d, kMaxDirEntries, [&](const struct dirent* ent) {
        const std::string_view name{ent->d_name};
        out.text += std::string{name};
        std::string full = wants_dir + "/" + std::string{name};
        char target[4096];
        ssize_t n = ::readlink(full.c_str(), target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            out.text += " -> ";
            out.text += target;
        }
        out.text += '\n';
        return true;
    });
    out.enumeration_error = walk.enumeration_error;
    out.truncated = walk.truncated;
    return out;
}

/// A timer is enabled iff its unit file is symlinked into either the
/// documented default `timers.target.wants/` or the WantedBy=-declared
/// target's own `.wants/` dir (readlink, never resolve -- see
/// autoruns_parsers.hpp:timer_enabled_from_wants). Enabled::unknown when
/// NEITHER candidate `.wants` directory could even be opened, OR when a
/// consulted directory opened but then hit a real I/O error or its entry
/// cap partway through (the matching symlink could be among what wasn't
/// read) -- a genuine "cannot tell" in either case, not the common "not
/// linked" case.
///
/// `systemctl enable` (system scope) always writes the enablement symlink
/// under `/etc/systemd/system/<target>.wants/`; `systemctl --user enable`
/// (user scope) writes it under `/etc/systemd/user/<target>.wants/` --
/// NEVER `/etc/systemd/system`, which holds only system-scope enablement
/// state and has no relationship to a user timer regardless of where that
/// timer's unit file lives. Each scope's own global wants root is the one
/// location every GLOBAL enable of that scope writes to, so the candidate
/// list is scope-conditional: probed both next to the unit file itself
/// (covers the vendor-"static" case, where the unit ships its own
/// `.wants/` symlink alongside it -- this also covers a per-user timer's
/// own `~/.config/systemd/user/timers.target.wants`, since that IS the
/// unit's own directory for a per-user scan) AND, unconditionally, under
/// this scope's own global wants root.
///
/// Neither of those covers the single most common user-scope layout: a
/// vendor unit file living in a GLOBAL directory (e.g.
/// `/usr/lib/systemd/user`), enabled by one specific user via ordinary
/// `systemctl --user enable`, which writes the symlink into THAT USER's
/// OWN `~/.config/systemd/user/timers.target.wants` -- a directory that has
/// no relationship to the unit file's own location. `user_wants_bases`
/// (every enumerated user's own `~/.config/systemd/user`, collected once by
/// the caller) is checked too for user scope, so a global-directory unit
/// enabled by any one user is found regardless of which directory the
/// caller happened to discover it in.
Enabled timer_enabled(const std::string& unit_dir, const std::string& timer_filename,
                      const std::string& wanted_by, Scope scope,
                      const std::vector<std::string>& user_wants_bases = {}) {
    const std::string_view wants_root =
        scope == Scope::system ? "/etc/systemd/system" : "/etc/systemd/user";
    std::vector<std::string> wants_base_dirs = {unit_dir};
    if (unit_dir != wants_root) wants_base_dirs.emplace_back(wants_root);
    if (scope == Scope::user) {
        for (const auto& base : user_wants_bases)
            if (base != unit_dir) wants_base_dirs.push_back(base);
    }

    bool any_opened = false;
    bool any_incomplete = false; // a real I/O error OR a cap-truncation on any
                                 // consulted wants dir -- either way, the
                                 // matching symlink could be among what wasn't
                                 // read, so "no match found" isn't proof of
                                 // disabled (round 8's blocker: a capped scan
                                 // with no match silently read as a confident
                                 // Enabled::disabled).
    for (const auto& base : wants_base_dirs) {
        auto w1 = build_wants_listing(base + "/timers.target.wants");
        any_opened |= w1.opened;
        any_incomplete |= w1.enumeration_error || w1.truncated;
        if (w1.opened && timer_enabled_from_wants(w1.text, timer_filename)) return Enabled::enabled;
        if (!wanted_by.empty()) {
            auto w2 = build_wants_listing(base + "/" + wanted_by + ".wants");
            any_opened |= w2.opened;
            any_incomplete |= w2.enumeration_error || w2.truncated;
            if (w2.opened && timer_enabled_from_wants(w2.text, timer_filename)) return Enabled::enabled;
        }
    }
    // A wants directory that failed partway through enumeration, or hit its
    // entry cap, may have missed the very symlink that would have proven
    // this timer enabled -- reporting a confident `disabled` there is the
    // same false-negative "live persistence mechanism read as inert" defect
    // class this file's other fixes exist to close.
    if (any_incomplete) return Enabled::unknown;
    return any_opened ? Enabled::disabled : Enabled::unknown;
}

// ── systemd presence tri-state (spec: /run/systemd/system) ──────────────

enum class SystemdPresence { present, absent, undetermined };

SystemdPresence check_systemd_presence() {
    struct stat st{};
    if (::stat("/run/systemd/system", &st) == 0)
        return S_ISDIR(st.st_mode) ? SystemdPresence::present : SystemdPresence::undetermined;
    if (errno == ENOENT) return SystemdPresence::absent;
    return SystemdPresence::undetermined;
}

struct TimerScan {
    std::vector<Row> rows;
    bool any_dir_readable = false;
    bool any_truncated = false;      // a scanned dir hit its entry cap (AC4: row_cap)
    bool any_file_constrained = false; // a listed unit file failed to read for a real
                                       // reason (not a raced deletion) -- AC4
    std::string file_constrained_reason;
    bool any_permission_denied = false; // a candidate dir (e.g. one user's
                                        // ~/.config/systemd/user) refused to
                                        // open -- distinct from "absent",
                                        // matching lnx_cron_periodic's
                                        // partial_permission_denied treatment
};

/// A directory's (dev, ino) identity, for deduping two path spellings of the
/// same inode (e.g. /lib is a symlink to /usr/lib on every merged-usr
/// distro, so a naive per-path scan double-counts every unit under it).
/// nullopt when the path can't be stat'd (absent/permission-denied/etc) --
/// scan_systemd_timer_dir separately classifies that as its own outcome.
std::optional<std::pair<dev_t, ino_t>> dir_identity(const std::string& dir) {
    struct stat st{};
    if (::stat(dir.c_str(), &st) != 0) return std::nullopt;
    return std::make_pair(st.st_dev, st.st_ino);
}

/// Scans `dir` into `out` unless its (dev, ino) identity is already present
/// in `seen` (a merged-usr alias of a directory already scanned) -- appends
/// a newly-seen identity to `seen` so a later alias in the same call is
/// skipped too.
void scan_systemd_timer_dir_unique(const std::string& dir, Scope scope, const std::string& user,
                                    TimerScan& out,
                                    std::vector<std::pair<dev_t, ino_t>>& seen,
                                    const std::vector<std::string>& user_wants_bases = {});

void scan_systemd_timer_dir(const std::string& dir, Scope scope, const std::string& user,
                            TimerScan& out, const std::vector<std::string>& user_wants_bases = {}) {
    auto listing = list_dir(dir);
    if (!listing.opened) {
        if (listing.permission_denied) out.any_permission_denied = true;
        return; // absent / permission_denied / other -- not readable
    }
    out.any_dir_readable = true;
    if (listing.truncated) out.any_truncated = true;
    for (const auto& name : listing.names) {
        if (name.size() < 7 || name.compare(name.size() - 6, 6, ".timer") != 0) continue;
        std::string full = dir + "/" + name;
        auto content = read_file_bounded(full);
        if (!content) {
            // A raced deletion between listing and reading (ENOENT) is not
            // an error -- classify_read_error already treats it as benign
            // absence; anything else (permission denied, a refused
            // symlink, oversized, non-regular) is a real per-entry
            // constraint the dir-level "readable" status must not hide.
            auto cls = classify_read_error(content.error(), /*required_by_catalog=*/false);
            if (cls.support == YUZU_SUPPORT_CONSTRAINED)
                note_file_constraint(out.any_file_constrained, out.file_constrained_reason, cls.reason);
            continue;
        }
        auto fields = parse_systemd_timer(*content);

        Row row;
        row.source_id = scope == Scope::system ? SourceId::lnx_systemd_timers_system
                                                : SourceId::lnx_systemd_timers_user;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = full;
        row.entry = name;
        row.target =
            !fields.unit.empty() ? fields.unit : (name.substr(0, name.size() - 6) + ".service");
        // A unit may combine more than one trigger type (e.g. OnCalendar +
        // OnUnitActiveSec) -- report every populated one, not just the
        // first, so none is silently dropped from the row.
        {
            std::vector<std::string> triggers;
            if (!fields.on_calendar.empty()) triggers.push_back("OnCalendar=" + fields.on_calendar);
            if (!fields.on_boot_sec.empty()) triggers.push_back("OnBootSec=" + fields.on_boot_sec);
            if (!fields.on_active_sec.empty())
                triggers.push_back("OnUnitActiveSec=" + fields.on_active_sec);
            for (std::size_t i = 0; i < triggers.size(); ++i) {
                if (i) row.args += "; ";
                row.args += triggers[i];
            }
        }
        row.enabled = timer_enabled(dir, name, fields.wanted_by, scope, user_wants_bases);
        row.scope = scope;
        row.user = user;
        row.signed_state = Signed::not_checked;
        row.mtime = mtime_of(full);
        out.rows.push_back(std::move(row));
    }
}

void scan_systemd_timer_dir_unique(const std::string& dir, Scope scope, const std::string& user,
                                    TimerScan& out,
                                    std::vector<std::pair<dev_t, ino_t>>& seen,
                                    const std::vector<std::string>& user_wants_bases) {
    auto id = dir_identity(dir);
    if (id && std::find(seen.begin(), seen.end(), *id) != seen.end()) return;
    if (id) seen.push_back(*id);
    scan_systemd_timer_dir(dir, scope, user, out, user_wants_bases);
}

/// Combines a TimerScan's cap-truncation and per-file constraint flags into
/// one (support, reason) pair for the source's status line -- row_cap and a
/// file-read constraint are independent conditions, so both are named when
/// both occurred.
std::pair<YuzuSupportLevel, std::string> timer_scan_status(const TimerScan& scan) {
    if (!scan.any_truncated && !scan.any_file_constrained && !scan.any_permission_denied)
        return {YUZU_SUPPORT_SUPPORTED, "-"};
    std::string reason;
    if (scan.any_permission_denied) reason = "partial_permission_denied";
    if (scan.any_file_constrained)
        reason += (reason.empty() ? "" : ",") + scan.file_constrained_reason;
    if (scan.any_truncated) reason += (reason.empty() ? "" : ",") + std::string{"row_cap"};
    return {YUZU_SUPPORT_CONSTRAINED, reason};
}

/// lnx_systemd_timers_user's own catalog-declared level is CONSTRAINED (the
/// scanned search-path set omits several standard `systemd --user` unit
/// roots -- a permanent, documented gap, autoruns_catalog.hpp's third
/// exception), so a would-be-Supported timer_scan_status result must be
/// downgraded, and any other Constrained result must still name this
/// permanent gap alongside its own reason. Never emits Supported.
std::pair<YuzuSupportLevel, std::string> apply_narrow_search_path_coverage(
    YuzuSupportLevel support, std::string reason) {
    if (support == YUZU_SUPPORT_SUPPORTED) return {YUZU_SUPPORT_CONSTRAINED, "narrow_search_path_coverage"};
    reason += ",narrow_search_path_coverage";
    return {support, reason};
}

/// The full 3-way `lnx_systemd_timers_user` status decision, extracted so
/// each of production's three mutually-exclusive branches (a readable
/// directory somewhere; `/home` itself permission-denied; no readable
/// directory and `/home` genuinely absent) is independently unit-testable
/// without needing 3 different real filesystem states (PR #4154 round 8's
/// should-fix: the one existing dispatch test only ever reaches whichever
/// single branch this host's own `/run/systemd/system` state happens to
/// hit, so a later edit removing the `apply_narrow_search_path_coverage`
/// call from either of the other two branches would leave every test
/// green).
std::tuple<YuzuSupportLevel, std::string, std::size_t> systemd_user_timer_status(
    bool any_dir_readable, bool home_listing_opened, bool home_listing_permission_denied,
    const TimerScan& scan) {
    if (any_dir_readable || home_listing_opened) {
        const auto [scan_support, scan_reason] = timer_scan_status(scan);
        const auto [support, reason] = apply_narrow_search_path_coverage(scan_support, scan_reason);
        return {support, reason, scan.rows.size()};
    }
    if (home_listing_permission_denied) {
        const auto [support, reason] =
            apply_narrow_search_path_coverage(YUZU_SUPPORT_CONSTRAINED, "permission_denied");
        return {support, reason, std::size_t{0}};
    }
    // Every present-systemd result routes through the same helper --
    // including this terminal "no readable user-unit directory and /home
    // itself is absent" case, which used to emit a bare Supported that
    // contradicted this source's own catalog declaration.
    const auto [support, reason] = apply_narrow_search_path_coverage(YUZU_SUPPORT_SUPPORTED, "-");
    return {support, reason, std::size_t{0}};
}

/// Rung-2 fallback (autoruns/collect_linux#1, docs/wave7/integration-
/// autoruns-linux.md) -- used ONLY when zero of the three system unit dirs
/// were readable. Heuristic, not a fixture-tested pure parser: real
/// `systemctl list-timers --no-legend` rows carry multi-word timestamp
/// columns that don't reduce to a stable positional split, but UNIT and
/// ACTIVATES are always the last two whitespace tokens and never contain
/// whitespace themselves -- so the last two tokens are taken directly,
/// guarded by the `.timer` / service-name suffix check.
struct FallbackTimer {
    std::string unit;
    std::string activates;
};

/// Drops a possibly-partial trailing line from subprocess output that did
/// NOT terminate cleanly (deadline/cancelled/signaled/line_limit) -- a
/// non-clean stop can cut the buffered output mid-write, and a line with no
/// trailing newline may be a partial write (e.g. a truncated ACTIVATES
/// column). Never trims a clean run's output, and never trims a clean
/// run's real final line even if it happens to lack a trailing newline
/// (systemctl's own output always ends with one, so a missing one is
/// itself evidence of truncation only on a non-clean stop).
std::string_view trim_possibly_truncated_tail(std::string_view output, bool exited_cleanly) {
    if (exited_cleanly || output.empty() || output.back() == '\n') return output;
    const auto last_nl = output.find_last_of('\n');
    return last_nl == std::string_view::npos ? std::string_view{} : output.substr(0, last_nl + 1);
}

std::vector<FallbackTimer> parse_list_timers_fallback(std::string_view text) {
    std::vector<FallbackTimer> out;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string_view line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
        std::vector<std::string_view> tokens;
        std::size_t tp = 0;
        while (tp < line.size()) {
            while (tp < line.size() && line[tp] == ' ') ++tp;
            std::size_t start = tp;
            while (tp < line.size() && line[tp] != ' ') ++tp;
            if (tp > start) tokens.push_back(line.substr(start, tp - start));
        }
        if (tokens.size() >= 2) {
            std::string_view unit = tokens[tokens.size() - 2];
            std::string_view activates = tokens.back();
            constexpr std::string_view kTimerSuffix = ".timer";
            if (unit.size() > kTimerSuffix.size() &&
                unit.substr(unit.size() - kTimerSuffix.size()) == kTimerSuffix) {
                out.push_back(FallbackTimer{std::string{unit}, std::string{activates}});
            }
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    return out;
}

} // namespace

// `collect_linux` itself (below) is excluded when
// YUZU_AUTORUNS_LINUX_UNIT_TEST_INTERNALS_ONLY is defined -- the seam
// test_autoruns_linux_local.cpp uses to #include this TU directly and reach
// the internal-linkage read_file_bounded/classify_read_error for a
// constructed-fixture unit test, without pulling the rung-2 subprocess
// fallback's runner symbols (probe_tool_path / run_bounded_subprocess /
// forward_runner_failure) into the test binary's link. Never defined by
// this TU's own (real) build -- meson.build does not set it.
#ifndef YUZU_AUTORUNS_LINUX_UNIT_TEST_INTERNALS_ONLY

int collect_linux(yuzu::CommandContext& ctx, std::string_view filter) {
    // ── /etc/crontab (system format, required-by-catalog file) ──────────
    if (!source_wanted(filter, SourceId::lnx_etc_crontab)) {
        ctx.write_output(format_source_status(SourceId::lnx_etc_crontab, YUZU_SUPPORT_SUPPORTED,
                                              std::nullopt, "filtered"));
    } else {
        const SourceId id = SourceId::lnx_etc_crontab;
        auto content = read_file_bounded("/etc/crontab");
        if (content) {
            auto parsed = parse_crontab(*content, /*system_format=*/true);
            const std::int64_t mtime = mtime_of("/etc/crontab");
            std::size_t n = 0;
            for (const auto& e : parsed.entries) {
                Row row;
                row.source_id = id;
                row.catalog_version = kAutorunSourceCatalogVersion;
                row.location = "/etc/crontab";
                row.entry = e.schedule;
                row.target = e.command;
                row.enabled = Enabled::enabled;
                row.scope = Scope::system;
                row.user = e.user;
                row.signed_state = Signed::not_checked;
                row.mtime = mtime;
                ctx.write_output(format_row(row));
                ++n;
            }
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_SUPPORTED, n, "-"));
        } else {
            auto cls = classify_read_error(content.error(), /*required_by_catalog=*/true);
            ctx.write_output(format_source_status(id, cls.support, std::size_t{0}, cls.reason));
        }
    }

    // ── /etc/cron.d/* (system format, run-parts-valid names only) ───────
    if (!source_wanted(filter, SourceId::lnx_cron_d)) {
        ctx.write_output(format_source_status(SourceId::lnx_cron_d, YUZU_SUPPORT_SUPPORTED,
                                              std::nullopt, "filtered"));
    } else {
        const SourceId id = SourceId::lnx_cron_d;
        auto listing = list_dir("/etc/cron.d");
        if (!listing.opened) {
            YuzuSupportLevel support = listing.absent ? YUZU_SUPPORT_SUPPORTED : YUZU_SUPPORT_CONSTRAINED;
            std::string reason =
                listing.absent ? "absent" : (listing.permission_denied ? "permission_denied" : listing.other_token);
            ctx.write_output(format_source_status(id, support, std::size_t{0}, reason));
        } else {
            std::size_t n = 0;
            bool any_file_constrained = false;
            std::string file_constrained_reason;
            for (const auto& name : listing.names) {
                if (!run_parts_valid_name(name)) continue;
                std::string full = "/etc/cron.d/" + name;
                auto content = read_file_bounded(full);
                if (!content) {
                    auto cls = classify_read_error(content.error(), /*required_by_catalog=*/false);
                    if (cls.support == YUZU_SUPPORT_CONSTRAINED)
                        note_file_constraint(any_file_constrained, file_constrained_reason, cls.reason);
                    continue;
                }
                auto parsed = parse_crontab(*content, /*system_format=*/true);
                const std::int64_t mtime = mtime_of(full);
                for (const auto& e : parsed.entries) {
                    Row row;
                    row.source_id = id;
                    row.catalog_version = kAutorunSourceCatalogVersion;
                    row.location = full;
                    row.entry = e.schedule;
                    row.target = e.command;
                    row.enabled = Enabled::enabled;
                    row.scope = Scope::system;
                    row.user = e.user;
                    row.signed_state = Signed::not_checked;
                    row.mtime = mtime;
                    ctx.write_output(format_row(row));
                    ++n;
                }
            }
            std::string reason;
            if (any_file_constrained) reason = file_constrained_reason;
            if (listing.truncated) reason += (reason.empty() ? "" : ",") + std::string{"row_cap"};
            ctx.write_output(format_source_status(
                id, reason.empty() ? YUZU_SUPPORT_SUPPORTED : YUZU_SUPPORT_CONSTRAINED, n,
                reason.empty() ? "-" : reason));
        }
    }

    // ── /etc/cron.{hourly,daily,weekly,monthly}/* (listing only) ────────
    if (!source_wanted(filter, SourceId::lnx_cron_periodic)) {
        ctx.write_output(format_source_status(SourceId::lnx_cron_periodic, YUZU_SUPPORT_SUPPORTED,
                                              std::nullopt, "filtered"));
    } else {
        const SourceId id = SourceId::lnx_cron_periodic;
        std::size_t n = 0;
        bool any_dir_readable = false;
        bool any_permission_denied = false;
        bool any_truncated = false;
        for (const char* leaf : {"hourly", "daily", "weekly", "monthly"}) {
            std::string dir = std::string{"/etc/cron."} + leaf;
            auto listing = list_dir(dir);
            if (!listing.opened) {
                if (listing.permission_denied) any_permission_denied = true;
                continue;
            }
            any_dir_readable = true;
            if (listing.truncated) any_truncated = true;
            for (const auto& name : listing.names) {
                if (!run_parts_valid_name(name)) continue;
                std::string full = dir + "/" + name;
                if (::access(full.c_str(), X_OK) != 0) continue; // run-parts only executes +x files
                struct stat st{};
                if (::stat(full.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
                Row row;
                row.source_id = id;
                row.catalog_version = kAutorunSourceCatalogVersion;
                row.location = dir;
                row.entry = name;
                row.target = full;
                row.enabled = Enabled::enabled;
                row.scope = Scope::system;
                row.user = "-";
                row.signed_state = Signed::not_checked;
                row.mtime = static_cast<std::int64_t>(st.st_mtime);
                ctx.write_output(format_row(row));
                ++n;
            }
        }
        if (any_dir_readable) {
            // A permission-denied on a SIBLING cron.{hourly,...} directory
            // must not be silently absorbed into an unqualified "-" reason
            // just because at least one of the four was readable -- a
            // partial denial, like a capped (row_cap) directory, escalates
            // to CONSTRAINED: a genuine read failure always reports
            // CONSTRAINED (matches lnx_cron_d's identical escalation), never
            // SUPPORTED from row-truncation alone.
            std::string reason;
            if (any_permission_denied) reason = "partial_permission_denied";
            if (any_truncated) reason += (reason.empty() ? "" : ",") + std::string{"row_cap"};
            ctx.write_output(format_source_status(
                id, (any_truncated || any_permission_denied) ? YUZU_SUPPORT_CONSTRAINED
                                                              : YUZU_SUPPORT_SUPPORTED,
                n, reason.empty() ? "-" : reason));
        } else if (any_permission_denied) {
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_CONSTRAINED, std::size_t{0},
                                                  "permission_denied"));
        } else {
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_SUPPORTED, std::size_t{0}, "absent"));
        }
    }

    // ── per-user crontabs (/var/spool/cron/crontabs, /var/spool/cron) ───
    if (!source_wanted(filter, SourceId::lnx_user_crontabs)) {
        ctx.write_output(format_source_status(SourceId::lnx_user_crontabs, YUZU_SUPPORT_SUPPORTED,
                                              std::nullopt, "filtered"));
    } else {
        const SourceId id = SourceId::lnx_user_crontabs;
        std::size_t n = 0;
        bool any_dir_readable = false;
        bool any_permission_denied = false;
        bool any_file_permission_denied = false;
        bool any_truncated = false;
        for (const char* dir : {"/var/spool/cron/crontabs", "/var/spool/cron"}) {
            auto listing = list_dir(dir);
            if (!listing.opened) {
                if (listing.permission_denied) any_permission_denied = true;
                continue;
            }
            any_dir_readable = true;
            if (listing.truncated) any_truncated = true;
            for (const auto& name : listing.names) {
                std::string full = std::string{dir} + "/" + name;
                struct stat st{};
                if (::lstat(full.c_str(), &st) == 0 && !S_ISREG(st.st_mode)) continue; // e.g. a "crontabs" subdir under /var/spool/cron
                auto content = read_file_bounded(full);
                if (!content) {
                    if (content.error().errno_token == "EACCES" || content.error().errno_token == "EPERM")
                        any_file_permission_denied = true;
                    continue;
                }
                auto parsed = parse_crontab(*content, /*system_format=*/false);
                const std::int64_t mtime = mtime_of(full);
                for (const auto& e : parsed.entries) {
                    Row row;
                    row.source_id = id;
                    row.catalog_version = kAutorunSourceCatalogVersion;
                    row.location = full;
                    row.entry = e.schedule;
                    row.target = e.command;
                    row.enabled = Enabled::enabled;
                    row.scope = Scope::user;
                    row.user = name; // user = filename, per spec
                    row.signed_state = Signed::not_checked;
                    row.mtime = mtime;
                    ctx.write_output(format_row(row));
                    ++n;
                }
            }
        }
        if (n > 0) {
            // A denial on a sibling directory or file must not be silently
            // absorbed into an unqualified "-" just because SOME rows were
            // captured -- see lnx_cron_periodic's identical treatment above.
            // A genuine read failure always reports CONSTRAINED, matching
            // lnx_cron_d, never SUPPORTED from partial success alone.
            std::string reason;
            const bool any_denied = any_permission_denied || any_file_permission_denied;
            if (any_denied) reason = "partial_permission_denied";
            if (any_truncated) reason += (reason.empty() ? "" : ",") + std::string{"row_cap"};
            ctx.write_output(format_source_status(
                id, (any_truncated || any_denied) ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED,
                n, reason.empty() ? "-" : reason));
        } else if (any_permission_denied || any_file_permission_denied) {
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_CONSTRAINED, std::size_t{0},
                                                  "permission_denied"));
        } else if (any_dir_readable) {
            ctx.write_output(format_source_status(
                id, any_truncated ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED, std::size_t{0},
                any_truncated ? "row_cap" : "-"));
        } else {
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_SUPPORTED, std::size_t{0}, "absent"));
        }
    }

    // ── /etc/anacrontab (required-by-catalog file) ───────────────────────
    if (!source_wanted(filter, SourceId::lnx_anacrontab)) {
        ctx.write_output(format_source_status(SourceId::lnx_anacrontab, YUZU_SUPPORT_SUPPORTED,
                                              std::nullopt, "filtered"));
    } else {
        const SourceId id = SourceId::lnx_anacrontab;
        auto content = read_file_bounded("/etc/anacrontab");
        if (content) {
            auto entries = parse_anacrontab(*content);
            const std::int64_t mtime = mtime_of("/etc/anacrontab");
            for (const auto& e : entries) {
                Row row;
                row.source_id = id;
                row.catalog_version = kAutorunSourceCatalogVersion;
                row.location = "/etc/anacrontab";
                row.entry = e.job_id;
                row.target = e.command;
                row.args = e.period + " " + e.delay;
                row.enabled = Enabled::enabled;
                row.scope = Scope::system;
                row.user = "-";
                row.signed_state = Signed::not_checked;
                row.mtime = mtime;
                ctx.write_output(format_row(row));
            }
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_SUPPORTED, entries.size(), "-"));
        } else {
            auto cls = classify_read_error(content.error(), /*required_by_catalog=*/true);
            ctx.write_output(format_source_status(id, cls.support, std::size_t{0}, cls.reason));
        }
    }

    // ── /var/spool/at/* (at(1) job files) ────────────────────────────────
    if (!source_wanted(filter, SourceId::lnx_at_spool)) {
        ctx.write_output(format_source_status(SourceId::lnx_at_spool, YUZU_SUPPORT_SUPPORTED,
                                              std::nullopt, "filtered"));
    } else {
        const SourceId id = SourceId::lnx_at_spool;
        auto listing = list_dir("/var/spool/at");
        if (!listing.opened) {
            YuzuSupportLevel support = listing.absent ? YUZU_SUPPORT_SUPPORTED : YUZU_SUPPORT_CONSTRAINED;
            std::string reason =
                listing.absent ? "absent" : (listing.permission_denied ? "permission_denied" : listing.other_token);
            ctx.write_output(format_source_status(id, support, std::size_t{0}, reason));
        } else {
            std::size_t n = 0;
            bool any_permission_denied = false;
            for (const auto& name : listing.names) {
                if (!name.empty() && name.front() == '.') continue; // e.g. ".SEQ" sequence file
                std::string full = "/var/spool/at/" + name;
                struct stat lst{};
                if (::lstat(full.c_str(), &lst) == 0 && !S_ISREG(lst.st_mode)) continue; // e.g. "spool" subdir
                auto content = read_file_bounded(full);
                if (!content) {
                    if (content.error().errno_token == "EACCES" || content.error().errno_token == "EPERM")
                        any_permission_denied = true;
                    continue;
                }
                // Last non-comment, non-blank line is the queued command
                // (at(1) job files are a generated shell script; the queued
                // command is appended as the final line).
                std::string target;
                std::size_t pos = 0;
                while (pos <= content->size()) {
                    std::size_t nl = content->find('\n', pos);
                    std::string_view line =
                        nl == std::string::npos ? std::string_view{*content}.substr(pos)
                                                : std::string_view{*content}.substr(pos, nl - pos);
                    std::size_t nb = line.find_first_not_of(" \t");
                    if (nb != std::string_view::npos && line[nb] != '#') target = std::string{line};
                    if (nl == std::string::npos) break;
                    pos = nl + 1;
                }
                Row row;
                row.source_id = id;
                row.catalog_version = kAutorunSourceCatalogVersion;
                row.location = full;
                row.entry = name;
                row.target = target;
                row.enabled = Enabled::enabled;
                row.scope = Scope::system;
                row.user = "-"; // queuing user lives in an "# atrun uid=" comment; not modelled here
                row.signed_state = Signed::not_checked;
                row.mtime = mtime_of(full);
                ctx.write_output(format_row(row));
                ++n;
            }
            if (n > 0) {
                std::string reason;
                if (any_permission_denied) reason = "partial_permission_denied";
                if (listing.truncated) reason += (reason.empty() ? "" : ",") + std::string{"row_cap"};
                ctx.write_output(format_source_status(
                    id,
                    (listing.truncated || any_permission_denied) ? YUZU_SUPPORT_CONSTRAINED
                                                                  : YUZU_SUPPORT_SUPPORTED,
                    n, reason.empty() ? "-" : reason));
            } else if (any_permission_denied) {
                ctx.write_output(format_source_status(id, YUZU_SUPPORT_CONSTRAINED, std::size_t{0},
                                                      "permission_denied"));
            } else {
                ctx.write_output(format_source_status(
                    id, listing.truncated ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED,
                    std::size_t{0}, listing.truncated ? "row_cap" : "-"));
            }
        }
    }

    // ── systemd timers (system + user), tri-state on /run/systemd/system ─
    const bool want_sys_timers = source_wanted(filter, SourceId::lnx_systemd_timers_system);
    const bool want_user_timers = source_wanted(filter, SourceId::lnx_systemd_timers_user);
    if (!want_sys_timers)
        ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_system,
                                              YUZU_SUPPORT_SUPPORTED, std::nullopt, "filtered"));
    if (!want_user_timers)
        // CONSTRAINED even filtered-out -- matches this source's own
        // catalog-declared level (narrow_search_path_coverage, a permanent
        // gap), same principle as lnx_init_d's filtered branch above.
        ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_user,
                                              YUZU_SUPPORT_CONSTRAINED, std::nullopt, "filtered"));
    if (want_sys_timers || want_user_timers) {
        const SystemdPresence presence = check_systemd_presence();
        if (presence == SystemdPresence::absent) {
            if (want_sys_timers)
                ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_system,
                                                      YUZU_SUPPORT_UNSUPPORTED, std::size_t{0}, "no_systemd"));
            if (want_user_timers)
                ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_user,
                                                      YUZU_SUPPORT_UNSUPPORTED, std::size_t{0}, "no_systemd"));
        } else if (presence == SystemdPresence::undetermined) {
            if (want_sys_timers)
                ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_system,
                                                      YUZU_SUPPORT_CONSTRAINED, std::size_t{0},
                                                      "systemd_state_undetermined"));
            if (want_user_timers)
                ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_user,
                                                      YUZU_SUPPORT_CONSTRAINED, std::size_t{0},
                                                      "systemd_state_undetermined"));
        } else {
            if (want_sys_timers) {
                TimerScan scan;
                std::vector<std::pair<dev_t, ino_t>> seen_dirs;
                for (const char* dir :
                    {"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}) {
                    // /lib is a symlink to /usr/lib on every merged-usr distro (all current
                    // Ubuntu/Debian/Fedora) -- dedup by directory identity, not path spelling,
                    // or every vendor timer is enumerated and emitted twice.
                    scan_systemd_timer_dir_unique(dir, Scope::system, "-", scan, seen_dirs);
                }
                if (scan.any_dir_readable) {
                    for (const auto& row : scan.rows) ctx.write_output(format_row(row));
                    const auto [support, reason] = timer_scan_status(scan);
                    ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_system,
                                                          support, scan.rows.size(), reason));
                } else {
                    // Rung-2 fallback -- autoruns/collect_linux#1 (docs/wave7/
                    // integration-autoruns-linux.md). ONLY reached when none
                    // of the three system unit dirs could be enumerated.
                    auto tool = yuzu::agent::probe_tool_path({"/usr/bin/systemctl", "/bin/systemctl"});
                    std::vector<std::string> argv;
                    if (!tool.empty())
                        argv = {tool, "list-timers", "--all", "--no-pager", "--no-legend"};
                    auto res = yuzu::agent::run_bounded_subprocess(
                        argv, yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{20}});
                    yuzu::agent::forward_runner_failure(ctx, res);
                    const bool exited_cleanly =
                        res.termination_reason == yuzu::agent::TerminationReason::exited;
                    auto parsed = parse_list_timers_fallback(
                        trim_possibly_truncated_tail(res.output, exited_cleanly));
                    for (const auto& t : parsed) {
                        Row row;
                        row.source_id = SourceId::lnx_systemd_timers_system;
                        row.catalog_version = kAutorunSourceCatalogVersion;
                        row.location = "systemctl:list-timers";
                        row.entry = t.unit;
                        row.target = t.activates;
                        row.enabled = Enabled::unknown; // no wants-symlink evidence from this text
                        row.scope = Scope::system;
                        row.user = "-";
                        row.signed_state = Signed::not_checked;
                        row.mtime = 0;
                        ctx.write_output(format_row(row));
                    }
                    ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_system,
                                                          YUZU_SUPPORT_CONSTRAINED, parsed.size(),
                                                          "argv_fallback"));
                }
            }

            if (want_user_timers) {
                TimerScan scan;
                std::vector<std::pair<dev_t, ino_t>> seen_dirs;
                // Every enumerated user's own wants base, collected up front so a
                // vendor unit discovered in a GLOBAL directory (below) can still be
                // correlated against the specific user who ran `systemctl --user
                // enable` on it -- that enablement symlink lands in the enabling
                // user's own dir, which has no relationship to the unit file's
                // location (see timer_enabled's banner).
                std::vector<std::string> home_dirs;
                auto home_listing = list_dir("/home");
                if (home_listing.truncated) scan.any_truncated = true;
                if (!home_listing.opened && home_listing.permission_denied)
                    scan.any_permission_denied = true;
                if (home_listing.opened) {
                    for (const auto& user : home_listing.names)
                        home_dirs.push_back("/home/" + user + "/.config/systemd/user");
                }
                std::vector<std::string> user_wants_bases = home_dirs;
                user_wants_bases.emplace_back("/root/.config/systemd/user");

                // Per-home and root scans do NOT get user_wants_bases: each
                // one's own unit_dir already IS that user's wants base (see
                // timer_enabled's banner), so passing the full cross-user
                // list here would let a same-named timer enabled in ONE
                // user's directory falsely mark an unrelated, never-enabled
                // same-named timer in ANOTHER user's directory as enabled
                // too (matching is by symlink basename only, with no
                // per-user scoping once the list is passed through). Only
                // the two GLOBAL-directory scans below need the correlation
                // -- a unit discovered there has no home directory of its
                // own to serve as an implicit wants base.
                for (const auto& dir : home_dirs)
                    scan_systemd_timer_dir_unique(dir, Scope::user, owner_uid_string(dir), scan,
                                                  seen_dirs);
                scan_systemd_timer_dir_unique("/root/.config/systemd/user", Scope::user,
                                              owner_uid_string("/root/.config/systemd/user"), scan,
                                              seen_dirs);
                // Global user-unit search paths, consulted for EVERY user's systemd --user
                // instance regardless of home directory (standard entries in
                // `systemd-analyze unit-paths --user` on every systemd distro) -- omitting
                // these makes a `supported` status false-complete.
                scan_systemd_timer_dir_unique("/etc/systemd/user", Scope::user, "-", scan, seen_dirs,
                                              user_wants_bases);
                scan_systemd_timer_dir_unique("/usr/lib/systemd/user", Scope::user, "-", scan,
                                              seen_dirs, user_wants_bases);
                for (const auto& row : scan.rows) ctx.write_output(format_row(row));
                const auto [support, reason, row_count] = systemd_user_timer_status(
                    scan.any_dir_readable, home_listing.opened, home_listing.permission_denied, scan);
                ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_user, support,
                                                      row_count, reason));
            }
        }
    }

    // ── XDG autostart (system) ───────────────────────────────────────────
    if (!source_wanted(filter, SourceId::lnx_xdg_autostart_system)) {
        ctx.write_output(format_source_status(SourceId::lnx_xdg_autostart_system,
                                              YUZU_SUPPORT_SUPPORTED, std::nullopt, "filtered"));
    } else {
        const SourceId id = SourceId::lnx_xdg_autostart_system;
        auto listing = list_dir("/etc/xdg/autostart");
        if (!listing.opened) {
            YuzuSupportLevel support = listing.absent ? YUZU_SUPPORT_SUPPORTED : YUZU_SUPPORT_CONSTRAINED;
            std::string reason =
                listing.absent ? "absent" : (listing.permission_denied ? "permission_denied" : listing.other_token);
            ctx.write_output(format_source_status(id, support, std::size_t{0}, reason));
        } else {
            std::size_t n = 0;
            bool any_file_constrained = false;
            std::string file_constrained_reason;
            for (const auto& name : listing.names) {
                constexpr std::string_view kSuffix = ".desktop";
                if (name.size() <= kSuffix.size() || name.compare(name.size() - kSuffix.size(),
                                                                   kSuffix.size(), kSuffix) != 0)
                    continue;
                std::string full = "/etc/xdg/autostart/" + name;
                auto content = read_file_bounded(full);
                if (!content) {
                    auto cls = classify_read_error(content.error(), /*required_by_catalog=*/false);
                    if (cls.support == YUZU_SUPPORT_CONSTRAINED)
                        note_file_constraint(any_file_constrained, file_constrained_reason, cls.reason);
                    continue;
                }
                auto entry = parse_desktop_entry(*content);
                Row row;
                row.source_id = id;
                row.catalog_version = kAutorunSourceCatalogVersion;
                row.location = full;
                row.entry = name;
                row.target = entry.exec;
                row.enabled = entry.enabled;
                row.scope = Scope::system;
                row.user = "-";
                row.signed_state = Signed::not_checked;
                row.mtime = mtime_of(full);
                ctx.write_output(format_row(row));
                ++n;
            }
            std::string reason;
            if (any_file_constrained) reason = file_constrained_reason;
            if (listing.truncated) reason += (reason.empty() ? "" : ",") + std::string{"row_cap"};
            ctx.write_output(format_source_status(
                id, reason.empty() ? YUZU_SUPPORT_SUPPORTED : YUZU_SUPPORT_CONSTRAINED, n,
                reason.empty() ? "-" : reason));
        }
    }

    // ── XDG autostart (per-user, /home/*/.config/autostart only) ────────
    if (!source_wanted(filter, SourceId::lnx_xdg_autostart_user)) {
        ctx.write_output(format_source_status(SourceId::lnx_xdg_autostart_user,
                                              YUZU_SUPPORT_SUPPORTED, std::nullopt, "filtered"));
    } else {
        const SourceId id = SourceId::lnx_xdg_autostart_user;
        auto home_listing = list_dir("/home");
        std::size_t n = 0;
        bool any_truncated = home_listing.truncated;
        bool any_file_constrained = false;
        bool any_permission_denied = false;
        std::string file_constrained_reason;
        if (home_listing.opened) {
            for (const auto& user : home_listing.names) {
                std::string dir = "/home/" + user + "/.config/autostart";
                auto listing = list_dir(dir);
                if (!listing.opened) {
                    // Absent (ENOENT, "most users have none") is benign; a
                    // real denial (EACCES on a 0700 .config under a 0750
                    // home, the documented unprivileged agent's default
                    // posture) is a genuine constraint -- must accumulate
                    // it the same way the sibling per-user loops in this
                    // file (systemd-timer, at-spool, crontab) already do,
                    // never silently fold it into "not found".
                    if (listing.permission_denied) any_permission_denied = true;
                    continue;
                }
                if (listing.truncated) any_truncated = true;
                const std::string uid = owner_uid_string(dir);
                for (const auto& name : listing.names) {
                    constexpr std::string_view kSuffix = ".desktop";
                    if (name.size() <= kSuffix.size() ||
                        name.compare(name.size() - kSuffix.size(), kSuffix.size(), kSuffix) != 0)
                        continue;
                    std::string full = dir + "/" + name;
                    auto content = read_file_bounded(full);
                    if (!content) {
                        auto cls = classify_read_error(content.error(), /*required_by_catalog=*/false);
                        if (cls.support == YUZU_SUPPORT_CONSTRAINED)
                            note_file_constraint(any_file_constrained, file_constrained_reason, cls.reason);
                        continue;
                    }
                    auto entry = parse_desktop_entry(*content);
                    Row row;
                    row.source_id = id;
                    row.catalog_version = kAutorunSourceCatalogVersion;
                    row.location = full;
                    row.entry = name;
                    row.target = entry.exec;
                    row.enabled = entry.enabled;
                    row.scope = Scope::user;
                    row.user = uid;
                    row.signed_state = Signed::not_checked;
                    row.mtime = mtime_of(full);
                    ctx.write_output(format_row(row));
                    ++n;
                }
            }
            std::string reason;
            if (any_permission_denied) reason = "partial_permission_denied";
            if (any_file_constrained)
                reason += (reason.empty() ? "" : ",") + file_constrained_reason;
            if (any_truncated) reason += (reason.empty() ? "" : ",") + std::string{"row_cap"};
            ctx.write_output(format_source_status(
                id, reason.empty() ? YUZU_SUPPORT_SUPPORTED : YUZU_SUPPORT_CONSTRAINED, n,
                reason.empty() ? "-" : reason));
        } else if (home_listing.permission_denied) {
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_CONSTRAINED, std::size_t{0},
                                                  "permission_denied"));
        } else {
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_SUPPORTED, std::size_t{0}, "absent"));
        }
    }

    // ── /etc/rc.local (row only when present AND executable) ────────────
    // A bounded, symlink-refusing read reuses the same errno classification
    // every other required-ish file in this leg uses (classify_read_error),
    // so ENOENT -> supported/absent, a real read error (permission denied,
    // a refused symlink, a non-regular leaf) -> constrained/<reason>, and a
    // present-but-non-executable file is its own honest zero-row case --
    // never all four collapsed into the same unsupported|absent line
    // (which contradicted the catalog's own YUZU_SUPPORT_SUPPORTED
    // declaration for this source, and the spec's own worked example of
    // an absent /etc/rc.local as supported|0|absent).
    if (!source_wanted(filter, SourceId::lnx_rc_local)) {
        ctx.write_output(format_source_status(SourceId::lnx_rc_local, YUZU_SUPPORT_SUPPORTED,
                                              std::nullopt, "filtered"));
    } else {
        const SourceId id = SourceId::lnx_rc_local;
        auto content = read_file_bounded("/etc/rc.local");
        if (!content) {
            auto cls = classify_read_error(content.error(), /*required_by_catalog=*/false);
            ctx.write_output(format_source_status(id, cls.support, std::size_t{0}, cls.reason));
        } else if (::access("/etc/rc.local", X_OK) != 0) {
            ctx.write_output(
                format_source_status(id, YUZU_SUPPORT_SUPPORTED, std::size_t{0}, "not_executable"));
        } else {
            Row row;
            row.source_id = id;
            row.catalog_version = kAutorunSourceCatalogVersion;
            row.location = "/etc/rc.local";
            row.entry = "rc.local";
            row.target = "/etc/rc.local";
            row.enabled = Enabled::enabled;
            row.scope = Scope::system;
            row.user = "-";
            row.signed_state = Signed::not_checked;
            row.mtime = mtime_of("/etc/rc.local");
            ctx.write_output(format_row(row));
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_SUPPORTED, std::size_t{1}, "-"));
        }
    }

    // ── /etc/init.d/* (listing only -- always CONSTRAINED per catalog) ──
    if (!source_wanted(filter, SourceId::lnx_init_d)) {
        // CONSTRAINED even filtered-out -- the catalog declares lnx_init_d's
        // own intrinsic support level as CONSTRAINED (listing-only, no
        // runlevel-wiring read), and a filtered status must report that
        // source's own level, never a blanket SUPPORTED (autoruns_catalog.hpp).
        ctx.write_output(format_source_status(SourceId::lnx_init_d, YUZU_SUPPORT_CONSTRAINED,
                                              std::nullopt, "filtered"));
    } else {
        const SourceId id = SourceId::lnx_init_d;
        auto listing = list_dir("/etc/init.d");
        if (!listing.opened) {
            std::string reason =
                listing.absent ? "absent" : (listing.permission_denied ? "permission_denied" : listing.other_token);
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_CONSTRAINED, std::size_t{0}, reason));
        } else {
            std::size_t n = 0;
            for (const auto& name : listing.names) {
                std::string full = "/etc/init.d/" + name;
                struct stat st{};
                if (::stat(full.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
                Row row;
                row.source_id = id;
                row.catalog_version = kAutorunSourceCatalogVersion;
                row.location = "/etc/init.d";
                row.entry = name;
                row.target = full;
                row.enabled = Enabled::unknown; // SysV enablement is distro-dependent; not modelled
                row.scope = Scope::system;
                row.user = "-";
                row.signed_state = Signed::not_checked;
                row.mtime = static_cast<std::int64_t>(st.st_mtime);
                ctx.write_output(format_row(row));
                ++n;
            }
            ctx.write_output(format_source_status(
                id, YUZU_SUPPORT_CONSTRAINED, n,
                listing.truncated ? "listing_only,row_cap" : "listing_only"));
        }
    }

    return 0;
}

#endif // !YUZU_AUTORUNS_LINUX_UNIT_TEST_INTERNALS_ONLY

} // namespace yuzu::autoruns

#endif // __linux__
