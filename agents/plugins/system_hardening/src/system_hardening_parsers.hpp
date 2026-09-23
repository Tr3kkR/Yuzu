/**
 * system_hardening_parsers.hpp -- the PURE layer for system_hardening: the
 * per-OS key allowlists, the raw-value -> state mappers, the errno
 * classifier, the row formatter, and the collect loops that drive an
 * INJECTED reader. No OS call, no I/O, no platform header: the Linux/macOS
 * leg TUs supply the real reader (open/read, sysctlbyname); the unit suite
 * supplies a fake one and never spawns, sleeps or touches disk.
 *
 * ROW SCHEMA (one row per allowlisted key, always, in allowlist order):
 *   posture|<os>|<key>|<raw>|<state>
 * <state> is one of enabled, disabled, partial, unmodelled, absent,
 * unreadable. `enabled`/`disabled`/`partial` describe the HARDENING (a
 * protection that is on / off / on at a weaker level), NOT the sysctl's own
 * value: kernel.sysrq=0 is `enabled` (sysrq closed), kern.coredump=1 is
 * `disabled` (core dumps allowed). `unmodelled` = a value was read but this
 * table has no interpretation for it (the raw column still carries it).
 * `absent` (the OS definitively reports the key is not there) and `unreadable`
 * (it exists, or may exist, but the read failed) are distinct states; a failed
 * read NEVER reads as absent (the errno decides). ABSENCE IS NOT A FAILURE: an
 * optional key that is simply not present (Yama not built into the kernel, an
 * unknown sysctl oid) is the modal state on some hosts, so an `absent` row adds
 * NO reason token and does not lower the result status.
 *
 * <raw> is "-" when no value was read (absent/unreadable); an empty value that
 * WAS read (macOS kern.bootargs) is an empty column.
 *
 * REASON TOKENS (yuzu::shared::ConstraintAccumulator, one per UNREADABLE key;
 * an absent key adds none):
 *   <key>:eacces          -> unreadable (EACCES or EPERM) AND the run reports
 *                            PERMISSION_DENIED/PARTIAL
 *   <key>:errno_<n>       -> unreadable (any other errno)
 * ENOENT is the only errno that reads as `absent`, and it carries no token. The
 * Linux leg only ever hands this layer an ENOENT it has confirmed: a leaf ENOENT
 * whose /proc/sys is not a procfs mount arrives as ENODEV (remap_enoent_for_surface
 * below) and reads `unreadable` + `<key>:errno_19`, never a clean `absent`. A
 * run whose every key is a value or `absent` therefore reports OK/FULL; a run
 * with an `unreadable` key reports PERMISSION_DENIED/PARTIAL when any read was
 * refused (a denial outranks every other cause), else CONSTRAINED/PARTIAL --
 * select_status below decides, for every leg.
 *
 * EMPTY IS NOT FAILED: an empty macOS kern.bootargs is a successful read of
 * an empty string (sysctlbyname size probe rc=0, len=1 -- a lone NUL); the
 * mapper defines it `enabled` (no boot-arg overrides) and it adds no token.
 */
#pragma once

#include <constraint_accumulator.hpp>

#include <yuzu/plugin.h> // YuzuResultStatus / Completeness (C ABI: no OS types)
#include <yuzu/string_utils.hpp>

#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::system_hardening {

enum class PostureState { enabled, disabled, partial, unmodelled, absent, unreadable };

[[nodiscard]] constexpr std::string_view state_token(PostureState s) noexcept {
    switch (s) {
    case PostureState::enabled:    return "enabled";
    case PostureState::disabled:   return "disabled";
    case PostureState::partial:    return "partial";
    case PostureState::unmodelled: return "unmodelled";
    case PostureState::absent:     return "absent";
    case PostureState::unreadable: return "unreadable";
    }
    return "unmodelled";
}

inline constexpr std::array<std::string_view, 6> kStateTokens{
    "enabled", "disabled", "partial", "unmodelled", "absent", "unreadable"};

// ── value rules ─────────────────────────────────────────────────────────

/// Inclusive [lo, hi] integer range -> state. First matching rule wins; no
/// match is `unmodelled`.
struct ValueRule {
    std::int64_t lo;
    std::int64_t hi;
    PostureState state;
};

[[nodiscard]] constexpr PostureState apply_rules(std::span<const ValueRule> rules,
                                                 std::int64_t v) noexcept {
    for (const auto& r : rules)
        if (v >= r.lo && v <= r.hi) return r.state;
    return PostureState::unmodelled;
}

namespace rules {
using enum PostureState;

// Linux value semantics: Documentation/admin-guide/sysctl/{kernel,fs}.rst and
// Documentation/admin-guide/LSM/Yama.rst.
inline constexpr ValueRule kAslr[] = {{0, 0, disabled}, {1, 1, partial}, {2, 2, enabled}};
inline constexpr ValueRule kKptr[] = {{0, 0, disabled}, {1, 1, partial}, {2, 2, enabled}};
// Yama: 0 classic ptrace, 1 restricted to descendants (the hardened baseline),
// 2 admin-only, 3 no attach. Every non-zero level is an active restriction.
inline constexpr ValueRule kPtrace[] = {{0, 0, disabled}, {1, 3, enabled}};
inline constexpr ValueRule kBool[] = {{0, 0, disabled}, {1, 1, enabled}};
// 0 unprivileged BPF allowed; 1 locked off until reboot; 2 off but re-enableable by root.
inline constexpr ValueRule kBpf[] = {{0, 0, disabled}, {1, 2, enabled}};
// sysrq: 0 all functions off (hardened), 1 all on, 2..511 a function bitmask.
inline constexpr ValueRule kSysrq[] = {{0, 0, enabled}, {1, 1, disabled}, {2, 511, partial}};
// protected_fifos / protected_regular: 1 = restricted in world-writable sticky
// dirs, 2 = also group-writable sticky dirs.
inline constexpr ValueRule kProtectedFile[] = {{0, 0, disabled}, {1, 1, partial}, {2, 2, enabled}};
// suid_dumpable: 0 no dump (hardened), 1 debug (any dump), 2 root-readable only.
inline constexpr ValueRule kSuidDump[] = {{0, 0, enabled}, {1, 1, disabled}, {2, 2, partial}};

// kern.securelevel: -1/0 insecure, 1 secure, 2 highly secure (securelevel(7)).
inline constexpr ValueRule kSecurelevel[] = {{-1, 0, disabled}, {1, 1, partial}, {2, 2, enabled}};
// kern.coredump / kern.sugid_coredump: 1 = dumps allowed (hardening off).
inline constexpr ValueRule kCoreOff[] = {{0, 0, enabled}, {1, 1, disabled}};

} // namespace rules

// ── allowlists (the ONLY keys either leg ever reads) ────────────────────

struct LinuxKey {
    std::string_view key;
    std::string_view path;
    std::span<const ValueRule> rules;
};

// key -> path in ONE table; there is deliberately no /proc/sys walk and the
// action takes no parameters, so no request-supplied text reaches a path.
inline constexpr std::array<LinuxKey, 11> kLinuxAllowlist{{
    {"kernel.randomize_va_space", "/proc/sys/kernel/randomize_va_space", rules::kAslr},
    {"kernel.kptr_restrict", "/proc/sys/kernel/kptr_restrict", rules::kKptr},
    {"kernel.yama.ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope", rules::kPtrace},
    {"kernel.dmesg_restrict", "/proc/sys/kernel/dmesg_restrict", rules::kBool},
    {"kernel.unprivileged_bpf_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled", rules::kBpf},
    {"kernel.sysrq", "/proc/sys/kernel/sysrq", rules::kSysrq},
    {"fs.protected_hardlinks", "/proc/sys/fs/protected_hardlinks", rules::kBool},
    {"fs.protected_symlinks", "/proc/sys/fs/protected_symlinks", rules::kBool},
    {"fs.protected_fifos", "/proc/sys/fs/protected_fifos", rules::kProtectedFile},
    {"fs.protected_regular", "/proc/sys/fs/protected_regular", rules::kProtectedFile},
    {"fs.suid_dumpable", "/proc/sys/fs/suid_dumpable", rules::kSuidDump},
}};

enum class SysctlKind { integer, string };

struct MacosKey {
    std::string_view name;
    SysctlKind kind;
    std::span<const ValueRule> rules; // integer keys only
};

// kern.nx is deliberately absent: `unknown oid` on Apple Silicon (ENOENT).
inline constexpr std::array<MacosKey, 4> kMacosAllowlist{{
    {"kern.securelevel", SysctlKind::integer, rules::kSecurelevel},
    {"kern.coredump", SysctlKind::integer, rules::kCoreOff},
    {"kern.sugid_coredump", SysctlKind::integer, rules::kCoreOff},
    {"kern.bootargs", SysctlKind::string, {}},
}};

// ── pure mappers ────────────────────────────────────────────────────────

/// First line of `data`, ASCII-whitespace trimmed.
[[nodiscard]] inline std::string_view first_line_trimmed(std::string_view data) noexcept {
    if (const auto nl = data.find('\n'); nl != std::string_view::npos) data = data.substr(0, nl);
    const auto ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\0'; };
    while (!data.empty() && ws(data.front())) data.remove_prefix(1);
    while (!data.empty() && ws(data.back())) data.remove_suffix(1);
    return data;
}

/// Strict base-10 integer: the whole (trimmed) token or nullopt.
[[nodiscard]] inline std::optional<std::int64_t> parse_int(std::string_view raw) noexcept {
    raw = first_line_trimmed(raw);
    std::int64_t v = 0;
    const auto* end = raw.data() + raw.size();
    const auto [p, ec] = std::from_chars(raw.data(), end, v);
    if (raw.empty() || ec != std::errc{} || p != end) return std::nullopt;
    return v;
}

[[nodiscard]] inline PostureState evaluate_linux(std::string_view key, std::string_view raw) noexcept {
    for (const auto& k : kLinuxAllowlist) {
        if (k.key != key) continue;
        const auto v = parse_int(raw);
        return v ? apply_rules(k.rules, *v) : PostureState::unmodelled;
    }
    return PostureState::unmodelled;
}

[[nodiscard]] inline PostureState evaluate_macos_int(std::string_view name, std::int64_t v) noexcept {
    for (const auto& k : kMacosAllowlist)
        if (k.name == name && k.kind == SysctlKind::integer) return apply_rules(k.rules, v);
    return PostureState::unmodelled;
}

/// Only kern.bootargs is a string sysctl. Empty = a successful read of "no
/// boot-arg overrides" = enabled. A non-empty value is not interpreted (boot
/// args are an open vocabulary): unmodelled, raw column carries it.
[[nodiscard]] inline PostureState evaluate_macos_string(std::string_view name,
                                                        std::string_view raw) noexcept {
    if (name == "kern.bootargs")
        return first_line_trimmed(raw).empty() ? PostureState::enabled : PostureState::unmodelled;
    return PostureState::unmodelled;
}

// ── errno classification ────────────────────────────────────────────────

/// Only ENOENT means the key is not there; every other errno (EACCES, EPERM,
/// EIO, ...) is a failed read of a key that may well exist.
[[nodiscard]] constexpr PostureState classify_read_errno(int err) noexcept {
    return err == ENOENT ? PostureState::absent : PostureState::unreadable;
}

/// A leaf ENOENT is only evidence that a key is absent when the pseudo-filesystem it lives
/// on is actually there. `/proc/sys` hidden or replaced by the runtime (a `ProcSubset=pid`
/// mount, a container or chroot that does not expose it, a tmpfs overmount) turns EVERY read
/// into ENOENT without saying anything about the host's hardening, so an unconfirmed surface
/// remaps ENOENT to ENODEV: `unreadable` + `<key>:errno_19`, never a clean `absent`. Every
/// other errno passes through untouched. `surface_mounted` is decided by the Linux leg
/// (statfs magic of /proc/sys); this function is the pure half of that decision. The
/// sibling platform_security plugin applies the same rule to efivarfs/securityfs.
[[nodiscard]] constexpr int remap_enoent_for_surface(int err, bool surface_mounted) noexcept {
    return (err == ENOENT && !surface_mounted) ? ENODEV : err;
}

/// EACCES/EPERM: the read was refused. The one pair failure_token spells `:eacces`
/// and select_status turns into PERMISSION_DENIED.
[[nodiscard]] constexpr bool is_denied_errno(int err) noexcept {
    return err == EACCES || err == EPERM;
}

/// The reason token of a FAILED read: `<key>:eacces` | `<key>:errno_<n>`.
/// Absence is not a failure: for ENOENT (classified `absent`) there is no
/// token, so the result is nullopt and nothing reaches the accumulator.
[[nodiscard]] inline std::optional<std::string> failure_token(std::string_view key, int err) {
    if (classify_read_errno(err) == PostureState::absent) return std::nullopt;
    std::string t{key};
    if (is_denied_errno(err)) t += ":eacces";
    else t += ":errno_" + std::to_string(err);
    return t;
}

// ── rows ────────────────────────────────────────────────────────────────

// `os` and `key` are borrowed views into the constexpr allowlists / literals, never owned.
struct PostureRow {
    std::string_view os;
    std::string_view key;
    std::string raw; // "-" when nothing was read
    PostureState state;
    int err = 0; // errno of a FAILED read (0 for a value)
};

[[nodiscard]] inline std::string format_posture_row(const PostureRow& r) {
    std::string out = "posture|";
    out += r.os;   // fixed vocabulary: "linux" / "macos" / "windows"
    out += '|';
    out += r.key;  // allowlist literal
    out += '|';
    out += yuzu::util::safe_output_field(r.raw); // OS-supplied text
    out += '|';
    out += state_token(r.state);
    return out;
}

/// The one row `execute()` writes after an internal error: the same five fields as every posture
/// row, so a schema-driven consumer maps it like any other (`os` is the host leg, the cause sits in
/// `key`, nothing was read). `os` is one of the fixed vocabulary, never OS-supplied text.
[[nodiscard]] inline std::string format_internal_error_row(std::string_view os) {
    std::string out = "constrained|";
    out += os;
    out += "|internal_error|-|";
    out += state_token(PostureState::unreadable);
    return out;
}

// ── collect loops over an injected reader ───────────────────────────────

/// What a reader returns. err == 0: a successful read (Linux `text`; macOS
/// `ival` for integer keys, `text` for string keys). err != 0: the read
/// failed with that errno and the value fields are ignored.
struct ReadOutcome {
    int err = 0;
    std::int64_t ival = 0;
    std::string text;
};

/// A read that returned errno `err`: an `absent` row with NO token for ENOENT,
/// otherwise an `unreadable` row whose one token is recorded in `acc` (the only
/// thing that can move the result status off OK/FULL).
[[nodiscard]] inline PostureRow failed_row(std::string_view os, std::string_view key, int err,
                                           yuzu::shared::ConstraintAccumulator& acc) {
    if (const auto token = failure_token(key, err)) acc.add_failure(*token);
    return {os, key, "-", classify_read_errno(err), err};
}

// ── status selection (pure; the one decision every leg shares) ──────────

[[nodiscard]] inline bool any_denied(std::span<const PostureRow> rows) noexcept {
    for (const auto& r : rows)
        if (is_denied_errno(r.err)) return true;
    return false;
}

struct PostureStatus {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    std::string provenance;
};

/// PERMISSION_DENIED/PARTIAL when any read was refused (a denial outranks every other
/// cause), else CONSTRAINED/PARTIAL when any token exists, else OK/FULL with no provenance.
[[nodiscard]] inline PostureStatus select_status(const yuzu::shared::ConstraintAccumulator& acc,
                                                 bool denied) {
    if (denied)
        return {YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                acc.reason()};
    if (acc.any_failure())
        return {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL, acc.reason()};
    return {YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, {}};
}

/// `read(path)` -> ReadOutcome. One row per kLinuxAllowlist entry, in order.
///
/// Canary (a backstop): any ONE key legitimately not existing is a real, per-key `absent`
/// (some kernels lack `kernel.yama.ptrace_scope`, for instance, and that alone is not
/// suspicious). ALL ELEVEN keys reading ENOENT together is a different fact -- it means
/// `/proc/sys` itself is not the tree this plugin expects, not that every hardening knob
/// coincidentally vanished. The Linux leg already remaps ENOENT from an unconfirmed
/// /proc/sys (remap_enoent_for_surface), so the ordinary hidden-surface case never reaches
/// here as ENOENT; the canary stays for a confirmed procfs mount that still hides every key.
/// That aggregate case adds one `proc_sys:not_visible` token so the result downgrades to
/// CONSTRAINED; it does not change any individual row, which is still reporting a true fact.
template <typename Reader>
[[nodiscard]] std::vector<PostureRow> collect_linux_posture(Reader&& read,
                                                            yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<PostureRow> rows;
    rows.reserve(kLinuxAllowlist.size());
    std::size_t enoent_count = 0;
    for (const auto& k : kLinuxAllowlist) {
        const ReadOutcome o = read(k.path);
        if (o.err != 0) {
            if (o.err == ENOENT) ++enoent_count;
            rows.push_back(failed_row("linux", k.key, o.err, acc));
            continue;
        }
        std::string raw{first_line_trimmed(o.text)};
        const auto state = evaluate_linux(k.key, raw);
        rows.push_back({"linux", k.key, std::move(raw), state});
    }
    if (enoent_count == kLinuxAllowlist.size())
        acc.add_failure("proc_sys:not_visible");
    return rows;
}

/// `read(name, kind)` -> ReadOutcome. One row per kMacosAllowlist entry.
template <typename Reader>
[[nodiscard]] std::vector<PostureRow> collect_macos_posture(Reader&& read,
                                                            yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<PostureRow> rows;
    rows.reserve(kMacosAllowlist.size());
    for (const auto& k : kMacosAllowlist) {
        const ReadOutcome o = read(k.name, k.kind);
        if (o.err != 0) {
            rows.push_back(failed_row("macos", k.name, o.err, acc));
            continue;
        }
        if (k.kind == SysctlKind::integer) {
            rows.push_back({"macos", k.name, std::to_string(o.ival), evaluate_macos_int(k.name, o.ival)});
        } else {
            std::string raw{first_line_trimmed(o.text)};
            const auto state = evaluate_macos_string(k.name, raw);
            // An empty value is a real read: the raw column stays empty ("-" means "nothing read").
            rows.push_back({"macos", k.name, std::move(raw), state});
        }
    }
    return rows;
}

} // namespace yuzu::system_hardening
