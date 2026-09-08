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

#include <yuzu/agent/runner_status.hpp>
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp>

#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <expected>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
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
    // Fallback: any other errno token (e.g. "ENOTDIR", "ERRNO_13") lower-
    // cased so every reason in this schema stays lower_snake_case for a
    // downstream string-matching consumer, matching permission_denied /
    // symlink_refused / oversized / not_regular / absent above.
    std::string reason = err.errno_token;
    for (char& c : reason) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return {YUZU_SUPPORT_CONSTRAINED, reason};
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
        else out.other_token = errno_token_for(e);
        return out;
    }
    out.opened = true;
    struct DirGuard {
        DIR* d;
        ~DirGuard() {
            if (d) ::closedir(d);
        }
    } guard{d};
    while (struct dirent* ent = ::readdir(d)) {
        std::string_view name{ent->d_name};
        if (name == "." || name == "..") continue;
        if (out.names.size() >= cap) {
            // Probe one more real entry before declaring truncation -- a
            // directory with exactly `cap` entries is not truncated.
            do {
                ent = ::readdir(d);
            } while (ent != nullptr && (std::string_view{ent->d_name} == "." ||
                                        std::string_view{ent->d_name} == ".."));
            out.truncated = ent != nullptr;
            break;
        }
        out.names.emplace_back(name);
    }
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
    std::size_t count = 0;
    while (struct dirent* ent = ::readdir(d)) {
        if (count >= kMaxDirEntries) break;
        std::string_view name{ent->d_name};
        if (name == "." || name == "..") continue;
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
        ++count;
    }
    return out;
}

/// A timer is enabled iff its unit file is symlinked into either the
/// documented default `timers.target.wants/` or the WantedBy=-declared
/// target's own `.wants/` dir (readlink, never resolve -- see
/// autoruns_parsers.hpp:timer_enabled_from_wants). Enabled::unknown only
/// when NEITHER candidate `.wants` directory could even be opened -- a
/// genuine "cannot tell", not the common "not linked" case.
///
/// `systemctl enable` always writes the enablement symlink under
/// `/etc/systemd/system/<target>.wants/`, pointing back at the unit file
/// wherever it actually lives -- for a package-installed timer that is
/// `/usr/lib/systemd/system` or `/lib/systemd/system`, NOT the directory
/// being scanned. So the wants-dir candidates are probed both next to the
/// unit file itself (covers the vendor-"static" case, where the unit ships
/// its own `.wants/` symlink alongside it, and the `/etc/systemd/system`
/// scan pass) AND, unconditionally, under `/etc/systemd/system` -- the one
/// location every `systemctl enable` writes to regardless of where the unit
/// file lives.
Enabled timer_enabled(const std::string& unit_dir, const std::string& timer_filename,
                      const std::string& wanted_by) {
    static constexpr std::string_view kSystemWantsBase = "/etc/systemd/system";
    std::vector<std::string> wants_base_dirs = {unit_dir};
    if (unit_dir != kSystemWantsBase) wants_base_dirs.emplace_back(kSystemWantsBase);

    bool any_opened = false;
    for (const auto& base : wants_base_dirs) {
        auto w1 = build_wants_listing(base + "/timers.target.wants");
        any_opened |= w1.opened;
        if (w1.opened && timer_enabled_from_wants(w1.text, timer_filename)) return Enabled::enabled;
        if (!wanted_by.empty()) {
            auto w2 = build_wants_listing(base + "/" + wanted_by + ".wants");
            any_opened |= w2.opened;
            if (w2.opened && timer_enabled_from_wants(w2.text, timer_filename)) return Enabled::enabled;
        }
    }
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
    bool any_truncated = false; // a scanned dir hit its entry cap (AC4: row_cap)
};

void scan_systemd_timer_dir(const std::string& dir, Scope scope, const std::string& user,
                            TimerScan& out) {
    auto listing = list_dir(dir);
    if (!listing.opened) return; // absent / permission_denied / other -- not readable
    out.any_dir_readable = true;
    if (listing.truncated) out.any_truncated = true;
    for (const auto& name : listing.names) {
        if (name.size() < 7 || name.compare(name.size() - 6, 6, ".timer") != 0) continue;
        std::string full = dir + "/" + name;
        auto content = read_file_bounded(full);
        if (!content) continue; // unreadable individual unit -- dir itself still counts readable
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
        row.enabled = timer_enabled(dir, name, fields.wanted_by);
        row.scope = scope;
        row.user = user;
        row.signed_state = Signed::not_checked;
        row.mtime = mtime_of(full);
        out.rows.push_back(std::move(row));
    }
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
    if (source_wanted(filter, SourceId::lnx_etc_crontab)) {
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
    if (source_wanted(filter, SourceId::lnx_cron_d)) {
        const SourceId id = SourceId::lnx_cron_d;
        auto listing = list_dir("/etc/cron.d");
        if (!listing.opened) {
            YuzuSupportLevel support = listing.absent ? YUZU_SUPPORT_SUPPORTED : YUZU_SUPPORT_CONSTRAINED;
            std::string reason =
                listing.absent ? "absent" : (listing.permission_denied ? "permission_denied" : listing.other_token);
            ctx.write_output(format_source_status(id, support, std::size_t{0}, reason));
        } else {
            std::size_t n = 0;
            for (const auto& name : listing.names) {
                if (!run_parts_valid_name(name)) continue;
                std::string full = "/etc/cron.d/" + name;
                auto content = read_file_bounded(full);
                if (!content) continue; // unreadable individual file -- skip, dir still supported
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
            ctx.write_output(format_source_status(
                id, listing.truncated ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED, n,
                listing.truncated ? "row_cap" : "-"));
        }
    }

    // ── /etc/cron.{hourly,daily,weekly,monthly}/* (listing only) ────────
    if (source_wanted(filter, SourceId::lnx_cron_periodic)) {
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
            // just because at least one of the four was readable -- but a
            // capped (row_cap) directory always escalates to CONSTRAINED,
            // matching the row_cap contract used everywhere else in this
            // codebase (a capped listing is not a complete one, AC4).
            std::string reason;
            if (any_permission_denied) reason = "partial_permission_denied";
            if (any_truncated) reason += (reason.empty() ? "" : ",") + std::string{"row_cap"};
            ctx.write_output(format_source_status(
                id, any_truncated ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED, n,
                reason.empty() ? "-" : reason));
        } else if (any_permission_denied) {
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_CONSTRAINED, std::size_t{0},
                                                  "permission_denied"));
        } else {
            ctx.write_output(format_source_status(id, YUZU_SUPPORT_SUPPORTED, std::size_t{0}, "absent"));
        }
    }

    // ── per-user crontabs (/var/spool/cron/crontabs, /var/spool/cron) ───
    if (source_wanted(filter, SourceId::lnx_user_crontabs)) {
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
            // A capped directory always escalates to CONSTRAINED (row_cap
            // contract, AC4).
            std::string reason;
            if (any_permission_denied || any_file_permission_denied) reason = "partial_permission_denied";
            if (any_truncated) reason += (reason.empty() ? "" : ",") + std::string{"row_cap"};
            ctx.write_output(format_source_status(
                id, any_truncated ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED, n,
                reason.empty() ? "-" : reason));
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
    if (source_wanted(filter, SourceId::lnx_anacrontab)) {
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
    if (source_wanted(filter, SourceId::lnx_at_spool)) {
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
                    id, listing.truncated ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED, n,
                    reason.empty() ? "-" : reason));
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
                for (const char* dir :
                    {"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}) {
                    scan_systemd_timer_dir(dir, Scope::system, "-", scan);
                }
                if (scan.any_dir_readable) {
                    for (const auto& row : scan.rows) ctx.write_output(format_row(row));
                    ctx.write_output(format_source_status(
                        SourceId::lnx_systemd_timers_system,
                        scan.any_truncated ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED,
                        scan.rows.size(), scan.any_truncated ? "row_cap" : "-"));
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
                    auto parsed = parse_list_timers_fallback(res.output);
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
                auto home_listing = list_dir("/home");
                if (home_listing.truncated) scan.any_truncated = true;
                if (home_listing.opened) {
                    for (const auto& user : home_listing.names) {
                        std::string dir = "/home/" + user + "/.config/systemd/user";
                        scan_systemd_timer_dir(dir, Scope::user, owner_uid_string(dir), scan);
                    }
                }
                scan_systemd_timer_dir("/root/.config/systemd/user", Scope::user,
                                       owner_uid_string("/root/.config/systemd/user"), scan);
                for (const auto& row : scan.rows) ctx.write_output(format_row(row));
                if (scan.any_dir_readable || home_listing.opened) {
                    ctx.write_output(format_source_status(
                        SourceId::lnx_systemd_timers_user,
                        scan.any_truncated ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED,
                        scan.rows.size(), scan.any_truncated ? "row_cap" : "-"));
                } else if (home_listing.permission_denied) {
                    ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_user,
                                                          YUZU_SUPPORT_CONSTRAINED, std::size_t{0},
                                                          "permission_denied"));
                } else {
                    ctx.write_output(format_source_status(SourceId::lnx_systemd_timers_user,
                                                          YUZU_SUPPORT_SUPPORTED, std::size_t{0}, "absent"));
                }
            }
        }
    }

    // ── XDG autostart (system) ───────────────────────────────────────────
    if (source_wanted(filter, SourceId::lnx_xdg_autostart_system)) {
        const SourceId id = SourceId::lnx_xdg_autostart_system;
        auto listing = list_dir("/etc/xdg/autostart");
        if (!listing.opened) {
            YuzuSupportLevel support = listing.absent ? YUZU_SUPPORT_SUPPORTED : YUZU_SUPPORT_CONSTRAINED;
            std::string reason =
                listing.absent ? "absent" : (listing.permission_denied ? "permission_denied" : listing.other_token);
            ctx.write_output(format_source_status(id, support, std::size_t{0}, reason));
        } else {
            std::size_t n = 0;
            for (const auto& name : listing.names) {
                constexpr std::string_view kSuffix = ".desktop";
                if (name.size() <= kSuffix.size() || name.compare(name.size() - kSuffix.size(),
                                                                   kSuffix.size(), kSuffix) != 0)
                    continue;
                std::string full = "/etc/xdg/autostart/" + name;
                auto content = read_file_bounded(full);
                if (!content) continue;
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
            ctx.write_output(format_source_status(
                id, listing.truncated ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED, n,
                listing.truncated ? "row_cap" : "-"));
        }
    }

    // ── XDG autostart (per-user, /home/*/.config/autostart only) ────────
    if (source_wanted(filter, SourceId::lnx_xdg_autostart_user)) {
        const SourceId id = SourceId::lnx_xdg_autostart_user;
        auto home_listing = list_dir("/home");
        std::size_t n = 0;
        bool any_truncated = home_listing.truncated;
        if (home_listing.opened) {
            for (const auto& user : home_listing.names) {
                std::string dir = "/home/" + user + "/.config/autostart";
                auto listing = list_dir(dir);
                if (!listing.opened) continue; // most users have none -- not an error
                if (listing.truncated) any_truncated = true;
                const std::string uid = owner_uid_string(dir);
                for (const auto& name : listing.names) {
                    constexpr std::string_view kSuffix = ".desktop";
                    if (name.size() <= kSuffix.size() ||
                        name.compare(name.size() - kSuffix.size(), kSuffix.size(), kSuffix) != 0)
                        continue;
                    std::string full = dir + "/" + name;
                    auto content = read_file_bounded(full);
                    if (!content) continue;
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
            ctx.write_output(format_source_status(
                id, any_truncated ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED, n,
                any_truncated ? "row_cap" : "-"));
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
    if (source_wanted(filter, SourceId::lnx_rc_local)) {
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
    if (source_wanted(filter, SourceId::lnx_init_d)) {
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
