/**
 * app_control_parsers.hpp -- pure state mappers, row formatters and fixture-dump
 * parsers for the app_control plugin (read-only WDAC / AppLocker posture).
 *
 * Free of the Win32 headers: plain string/integer transforms, testable on every OS
 * (tests/unit/test_app_control_parsers.cpp). It also owns every decision the Windows shell
 * takes (Win32 read classification, verdict selection, the CIM plan), so the shell only
 * performs I/O. Registry types, HRESULTs and wide
 * strings never cross this header -- app_control_win.cpp casts at the boundary and
 * hands over RegValueView / plain strings / WmiRow maps (an independent alias of
 * yuzu::shared::wmi::WmiRow so this compiles everywhere; bitlocker precedent).
 *
 * Rows (pipe-delimited; every untrusted field via yuzu::util::safe_output_field):
 *   wdac|<value_name>|<raw>|<state>          one per value under Control\CI\Policy
 *   wdac_cip|<policy_stem>|present           one per Active\*.cip policy file
 *   applocker|<collection>|<mode>|<rules>    one per AppLocker rule collection
 *   constrained|<reason>                     any failed step (typed status accompanies it)
 *   <action>|unsupported|windows_only_concept  non-Windows legs
 * <state>/<mode>: disabled | audit | enforced | unmodelled | absent. `unmodelled` = the
 * OS reported a value this mapper does not model; `absent` = the OS reported nothing.
 *
 * Fixture-dump formats (the-rig capture scripts emit exactly these):
 *   ci_policy_values.txt     name<TAB>u32|text|other<TAB>data   (other: data = byte length)
 *   applocker_wmi_probe.txt  `error=<token>`, or per-row `Key=Value` lines split by `--`
 * Empty input and malformed lines never throw: they record a failure token on the
 * returned ConstraintAccumulator (a failed read must not read as absent).
 */
#pragma once

#include <yuzu/plugin.h>         // YuzuResultStatus / Completeness (C ABI: no Windows types)
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

#include <constraint_accumulator.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yuzu::app_control {

using WmiRow = std::map<std::string, std::string>;

inline constexpr std::string_view kUnsupportedWindowsOnly = "windows_only_concept";

enum class PolicyState { disabled, audit, enforced, unmodelled };

inline constexpr std::string_view policy_state_name(PolicyState s) noexcept {
    constexpr std::string_view names[] = {"disabled", "audit", "enforced", "unmodelled"};
    return names[static_cast<std::size_t>(s)];
}

inline constexpr std::string_view kVerifiedAndReputableValue = "VerifiedAndReputablePolicyState";

/// Control\CI\Policy VerifiedAndReputablePolicyState (Smart App Control): 0 = off,
/// 1 = on/enforcing, 2 = evaluation (observing, not blocking -> audit). Any other
/// value is `unmodelled`, never coerced.
inline constexpr PolicyState map_ci_policy_state(std::uint32_t raw) noexcept {
    return raw == 0   ? PolicyState::disabled
           : raw == 1 ? PolicyState::enforced
           : raw == 2 ? PolicyState::audit
                      : PolicyState::unmodelled;
}

/// AppLocker (SrpV2 / CIM) EnforcementMode: 0 = audit only, 1 = enforce rules; any
/// other value is `unmodelled`. A missing EnforcementMode is `absent` at the row
/// layer (an optional), not a mapper input.
inline constexpr PolicyState map_enforcement_mode(std::uint32_t raw) noexcept {
    return raw == 0   ? PolicyState::audit
           : raw == 1 ? PolicyState::enforced
                      : PolicyState::unmodelled;
}

enum class RegValueKind { u32, text, other };

/// One value under Control\CI\Policy, already converted from the registry's
/// own types by app_control_win.cpp. `byte_len` matters only for `other`.
struct RegValueView {
    std::string name;
    RegValueKind kind = RegValueKind::other;
    std::uint32_t u32 = 0;
    std::string text;
    std::size_t byte_len = 0;
};

inline std::string format_wdac_row(const RegValueView& v) {
    const bool mapped = v.kind == RegValueKind::u32 && v.name == kVerifiedAndReputableValue;
    const auto state = policy_state_name(mapped ? map_ci_policy_state(v.u32) : PolicyState::unmodelled);
    const std::string raw = v.kind == RegValueKind::u32    ? std::to_string(v.u32)
                            : v.kind == RegValueKind::text ? yuzu::util::safe_output_field(v.text)
                                                           : "opaque_" + std::to_string(v.byte_len) + "B";
    return "wdac|" + yuzu::util::safe_output_field(v.name) + "|" + raw + "|" + std::string{state};
}

/// The CI\Policy key does not exist: a genuine "nothing configured", never a failed read.
inline std::string format_wdac_key_absent_row() { return "wdac|policy_key|-|absent"; }

inline constexpr std::string_view kCipExt = ".cip";

inline bool is_cip_filename(std::string_view name) noexcept {
    if (name.size() <= kCipExt.size())
        return false;
    const auto tail = name.substr(name.size() - kCipExt.size());
    return std::equal(tail.begin(), tail.end(), kCipExt.begin(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == b;
    });
}

inline std::string format_cip_row(std::string_view filename) {
    // caller checked is_cip_filename
    const auto stem = filename.substr(0, filename.size() - kCipExt.size());
    return "wdac_cip|" + yuzu::util::safe_output_field(stem) + "|present";
}

inline std::string format_cip_none_row() { return "wdac_cip|none|absent"; }

/// Most active *.cip rows emitted; a directory holding more records the `row_cap` failure.
inline constexpr std::size_t kMaxCipFiles = 64;

/// One scan of CodeIntegrity\CiPolicies\Active. The Windows shell owns only the std::filesystem
/// calls and feeds every entry (then the iterator's terminal error) in here, so every decision
/// about what a result MEANS is unit-tested on every OS. The rule: "no policy files" is a
/// definitive absence only when the directory is absent or was read cleanly and held none; any
/// failed stat or iterator error is recorded as a failure and suppresses the absent row.
class CipScan {
public:
    /// Failures land in `acc`; a permission refusal also sets `denied` (PERMISSION_DENIED status).
    CipScan(yuzu::shared::ConstraintAccumulator& acc, bool& denied) : acc_(acc), denied_(denied) {}

    /// One directory entry: UTF-8 leaf name, whether it is a regular file, and the error (if any)
    /// from asking the filesystem. A failed stat is a failure, never "not a .cip". Returns false
    /// once the row cap is hit; the caller stops iterating.
    bool observe(std::string_view leaf, bool is_regular, const std::error_code& stat_ec) {
        observed_any_ = true;
        if (stat_ec) {
            record(stat_ec, "cip_stat_failed");
            return true;
        }
        if (!is_regular || !is_cip_filename(leaf))
            return true;
        if (names_.size() >= kMaxCipFiles) {
            failed_ = true;
            acc_.add_failure("row_cap");
            return false;
        }
        names_.emplace_back(leaf);
        return true;
    }

    /// The directory iterator's terminal state, after the last observe(). A directory that does
    /// not exist (before any entry was seen) is a definitive absence, not a failure.
    void finish(const std::error_code& iter_ec) {
        if (iter_ec && !(iter_ec == std::errc::no_such_file_or_directory && !observed_any_))
            record(iter_ec, "cip_dir_failed");
        std::sort(names_.begin(), names_.end());
    }

    /// True iff the definitive "no active policy files" row is due.
    bool none_row_due() const noexcept { return names_.empty() && !failed_; }
    /// The .cip leaf names found, sorted; valid after finish().
    const std::vector<std::string>& names() const noexcept { return names_; }

private:
    void record(const std::error_code& ec, std::string_view what) {
        failed_ = true;
        if (ec == std::errc::permission_denied) {
            denied_ = true;
            acc_.add_failure("permission_denied");
        } else {
            acc_.add_failure(std::string{what} + "_" + std::to_string(ec.value()));
        }
    }

    yuzu::shared::ConstraintAccumulator& acc_;
    bool& denied_;
    std::vector<std::string> names_;
    bool observed_any_ = false;
    bool failed_ = false;
};

/// SrpV2 rule-collection subkey names, in output order.
inline constexpr std::array<std::string_view, 5> kApplockerCollections{"Appx", "Dll", "Exe", "Msi",
                                                                       "Script"};

inline std::string format_applocker_row(std::string_view collection,
                                        std::optional<std::uint32_t> mode, std::size_t rules) {
    const std::string_view mode_name =
        mode ? policy_state_name(map_enforcement_mode(*mode)) : std::string_view{"absent"};
    return "applocker|" + yuzu::util::safe_output_field(collection) + "|" +
           std::string{mode_name} + "|" + std::to_string(rules);
}

/// SrpV2 root absent: a genuine "nothing configured", never a failed read.
inline std::string format_applocker_none_row() { return "applocker|none|absent|0"; }

/// Any failed step: shown alongside the typed CONSTRAINED / PERMISSION_DENIED status.
inline std::string format_constrained_row(std::string_view reason) {
    return "constrained|" + yuzu::util::safe_output_field(reason);
}

inline std::string format_unsupported_row(std::string_view action) {
    return std::string{action} + "|unsupported|" + std::string{kUnsupportedWindowsOnly};
}

// ── Win32 read classification (pure; app_control_win.cpp static_asserts the numbers) ──

/// Plain integers so this header stays free of <windows.h>.
inline constexpr std::uint32_t kErrorSuccess = 0;
inline constexpr std::uint32_t kErrorFileNotFound = 2;
inline constexpr std::uint32_t kErrorPathNotFound = 3;
inline constexpr std::uint32_t kErrorAccessDenied = 5;

/// open_or_query: NOT_FOUND means the key/value definitively does not exist (absent).
/// enumerate: a RegEnumValueW / RegQueryInfoKeyW error is never an absence.
enum class ReadKind { open_or_query, enumerate };
enum class RegRead { ok, absent, unreadable };

/// `absent` carries NO token (no failure, status unaffected). `unreadable` carries exactly one:
/// `permission_denied` (+access_denied) for ERROR_ACCESS_DENIED, else `<what>_0x<hex>`.
struct ReadFailure {
    RegRead state;
    std::string token;
    bool access_denied{false};
};

inline ReadFailure classify_win32_read(std::string_view what, std::uint32_t err, ReadKind kind) {
    if (err == kErrorSuccess)
        return {RegRead::ok, {}, false};
    if (kind == ReadKind::open_or_query && (err == kErrorFileNotFound || err == kErrorPathNotFound))
        return {RegRead::absent, {}, false};
    if (err == kErrorAccessDenied)
        return {RegRead::unreadable, "permission_denied", true};
    char hex[9]; // lowercase, unpadded: ci_policy_enum_0xea for 234
    const auto [end, ec] = std::to_chars(hex, hex + sizeof hex, err, 16);
    return {RegRead::unreadable, std::string{what} + "_0x" + std::string{hex, end}, false};
}

/// Status / completeness / provenance / exit code from the accumulated failures.
struct ActionVerdict {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    std::string provenance;
    int rc;
    bool constrained_row_due;
};

/// No failure: OK / FULL / `source` / rc 0. Any failure: CONSTRAINED (PERMISSION_DENIED when
/// `denied`) / PARTIAL / the joined reasons / rc 1, and the `constrained|` row is due.
inline ActionVerdict select_verdict(const yuzu::shared::ConstraintAccumulator& acc, bool denied,
                                    std::string_view source) {
    if (!acc.any_failure())
        return {YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, std::string{source}, 0,
                false};
    return {denied ? YUZU_RESULT_STATUS_PERMISSION_DENIED : YUZU_RESULT_STATUS_CONSTRAINED,
            YUZU_RESULT_COMPLETENESS_PARTIAL, acc.reason(), 1, true};
}

// ── CIM leg: namespace floor, outcome classification, row mapping ───────────

/// wmi_bounded.hpp does NO namespace allowlisting: this plus is_allowed_cim_namespace()
/// is the caller-side floor.
inline constexpr std::string_view kCimNamespace = "root\\StandardCimv2\\Security\\ApplicationControl";
inline constexpr std::string_view kCimApplockerWql = "SELECT * FROM MSFT_ApplockerPolicy";

/// ASCII case-insensitive equality (WMI namespaces and property names are case-insensitive).
inline bool iequals(std::string_view a, std::string_view b) noexcept {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower(static_cast<unsigned char>(x)) ==
                      std::tolower(static_cast<unsigned char>(y));
           });
}

inline bool is_allowed_cim_namespace(std::string_view ns) noexcept {
    return iequals(ns, kCimNamespace);
}

enum class CimOutcome { ok, class_absent, permission_denied, failed };

inline bool ends_with(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

/// Classifies a wmi_bounded.hpp error token. class_absent = WBEM_E_INVALID_NAMESPACE
/// (0x8004100e) / WBEM_E_INVALID_CLASS (0x80041010): fall back to the SrpV2 walk.
/// permission_denied = WBEM_E_ACCESS_DENIED (0x80041003) / E_ACCESSDENIED (0x80070005).
/// Anything else is `failed` and stays constrained.
inline CimOutcome classify_cim_error(const std::optional<std::string>& error) {
    if (!error)
        return CimOutcome::ok;
    const std::string_view t{*error};
    if (ends_with(t, "0x8004100e") || ends_with(t, "0x80041010"))
        return CimOutcome::class_absent;
    if (ends_with(t, "0x80041003") || ends_with(t, "0x80070005"))
        return CimOutcome::permission_denied;
    return CimOutcome::failed;
}

/// Strict unsigned decimal parse: no sign, no whitespace, no trailing bytes.
inline std::optional<std::uint32_t> parse_u32(std::string_view s) noexcept {
    if (s.empty())
        return std::nullopt;
    std::uint32_t out = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
    if (ec != std::errc{} || ptr != s.data() + s.size())
        return std::nullopt;
    return out;
}

struct ApplockerRowData {
    std::string collection;
    std::optional<std::uint32_t> mode; // nullopt = absent
    std::size_t rules = 0;
};

namespace detail {
inline const std::string* find_prop(const WmiRow& row, std::string_view name) {
    for (const auto& [k, v] : row)
        if (iequals(k, name))
            return &v;
    return nullptr;
}
} // namespace detail

/// Maps one MSFT_ApplockerPolicy row. Property names are UNVERIFIED on hardware (the rig has no AppLocker provider namespace; see
/// app_control_win.cpp's banner): a row lacking `Collection`, `EnforcementMode` or
/// `RuleCount`, or with a non-numeric mode/count, returns nullopt and the caller
/// records `cim_row_unrecognised` rather than emitting a guessed value.
inline std::optional<ApplockerRowData> parse_cim_applocker_row(const WmiRow& row) {
    const auto* coll = detail::find_prop(row, "Collection");
    const auto* mode = detail::find_prop(row, "EnforcementMode");
    const auto* rules = detail::find_prop(row, "RuleCount");
    if (!coll || coll->empty() || !mode || !rules)
        return std::nullopt;
    const auto m = parse_u32(*mode);
    const auto r = parse_u32(*rules);
    if (!m || !r)
        return std::nullopt;
    return ApplockerRowData{*coll, *m, static_cast<std::size_t>(*r)};
}

/// The whole classify -> map -> fallback decision over one bounded CIM result, so the Windows
/// shell only performs the query and writes what this returns. `use_cim` is true only when the
/// class answered AND at least one row mapped; otherwise the caller walks SrpV2. A class that is
/// merely absent is expected and records nothing; every other failure lands in `failures`.
struct CimPlan {
    std::vector<ApplockerRowData> rows;
    std::vector<std::string> failures;
    bool denied{false};
    bool use_cim{false};
};

inline CimPlan plan_cim(const std::optional<std::string>& error, const std::vector<WmiRow>& rows,
                        bool truncated) {
    CimPlan plan;
    switch (classify_cim_error(error)) {
    case CimOutcome::ok:
        for (const auto& row : rows) {
            if (auto parsed = parse_cim_applocker_row(row))
                plan.rows.push_back(std::move(*parsed));
            else
                plan.failures.emplace_back("cim_row_unrecognised");
        }
        if (truncated)
            plan.failures.emplace_back("row_cap");
        plan.use_cim = !plan.rows.empty();
        break;
    case CimOutcome::class_absent:
        break; // expected on hosts without the class: not a failure
    case CimOutcome::permission_denied:
        plan.denied = true;
        plan.failures.emplace_back("permission_denied");
        break;
    case CimOutcome::failed:
        plan.failures.push_back(*error); // stable wmi_bounded.hpp token
        break;
    }
    return plan;
}

// ── Fixture-dump parsers (formats in the file header) ───────────────────────

namespace detail {
/// Non-blank CR-trimmed lines; empty input records `empty_input`.
inline std::vector<std::string_view> dump_lines(std::string_view text,
                                                yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<std::string_view> out;
    while (!text.empty()) {
        const auto nl = text.find('\n');
        auto line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (!line.empty())
            out.push_back(line);
    }
    if (out.empty())
        acc.add_failure("empty_input");
    return out;
}

/// Splits a line into exactly three tab-separated fields (non-empty first);
/// anything else records `malformed_line` and returns false.
inline bool tab3(std::string_view line, std::array<std::string_view, 3>& f,
                 yuzu::shared::ConstraintAccumulator& acc) {
    const auto t1 = line.find('\t');
    const auto t2 = t1 == std::string_view::npos ? t1 : line.find('\t', t1 + 1);
    if (t1 == 0 || t2 == std::string_view::npos ||
        line.find('\t', t2 + 1) != std::string_view::npos) {
        acc.add_failure("malformed_line");
        return false;
    }
    f = {line.substr(0, t1), line.substr(t1 + 1, t2 - t1 - 1), line.substr(t2 + 1)};
    return true;
}
} // namespace detail

struct CiPolicyDump {
    std::vector<RegValueView> values;
    yuzu::shared::ConstraintAccumulator acc;
};

inline CiPolicyDump parse_ci_policy_dump(std::string_view text) {
    CiPolicyDump out;
    for (const auto line : detail::dump_lines(text, out.acc)) {
        std::array<std::string_view, 3> f;
        if (!detail::tab3(line, f, out.acc))
            continue;
        RegValueView v;
        v.name = std::string{f[0]};
        const auto n = parse_u32(f[2]);
        if (f[1] == "u32" && n) {
            v.kind = RegValueKind::u32;
            v.u32 = *n;
        } else if (f[1] == "text") {
            v.kind = RegValueKind::text;
            v.text = std::string{f[2]};
        } else if (f[1] == "other" && n) {
            v.byte_len = *n;
        } else {
            out.acc.add_failure("malformed_line");
            continue;
        }
        out.values.push_back(std::move(v));
    }
    return out;
}

struct WmiProbeDump {
    std::optional<std::string> error;
    std::vector<WmiRow> rows;
    yuzu::shared::ConstraintAccumulator acc;
};

inline WmiProbeDump parse_wmi_probe_dump(std::string_view text) {
    WmiProbeDump out;
    WmiRow cur;
    const auto flush = [&] {
        if (!cur.empty())
            out.rows.push_back(std::move(cur));
        cur.clear();
    };
    for (const auto line : detail::dump_lines(text, out.acc)) {
        const auto eq = line.find('=');
        if (line == "--") {
            flush();
        } else if (eq == std::string_view::npos || eq == 0) {
            out.acc.add_failure("malformed_line");
        } else if (line.substr(0, eq) == "error") {
            out.error = std::string{line.substr(eq + 1)};
        } else {
            cur[std::string{line.substr(0, eq)}] = std::string{line.substr(eq + 1)};
        }
    }
    flush();
    return out;
}

} // namespace yuzu::app_control
