#pragma once

/// @file version_string.hpp
/// Shared, pure application-version normalization for the DEX (name, version)
/// identity. The SAME canonical form must come out of BOTH sources that feed the
/// identity — the on-device perf collector (Windows VS_FIXEDFILEINFO, agent) and
/// the crash/hang signal extractor (Windows-Error-Reporting AppVersion, agent) —
/// and the server re-applies `canon_version` at the projection boundary so a
/// hostile or non-Windows agent can never persist a non-canonical string. Pure
/// (no OS calls) so it is unit-tested on every host; header-only so agent-core
/// and server-core (both linking yuzu_sdk_dep) share one implementation.

#include <array>
#include <charconv>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace yuzu::util {

/// Format a Win32 VS_FIXEDFILEINFO version (dwFileVersionMS/LS) as the canonical
/// 4-group dotted quad "a.b.c.d" — HIWORD(ms).LOWORD(ms).HIWORD(ls).LOWORD(ls).
/// Always exactly 4 groups, no leading zeros (each field is 0..65535).
inline std::string format_file_version(std::uint32_t ms, std::uint32_t ls) {
    return std::format("{}.{}.{}.{}", (ms >> 16) & 0xffffu, ms & 0xffffu, (ls >> 16) & 0xffffu,
                       ls & 0xffffu);
}

/// Perf side: VS_FIXEDFILEINFO -> canonical version, with the "no real version"
/// case (all-zero fixed version) mapped to "" so it shares the single unknown
/// bucket with `canon_version("0.0.0.0")`. Pure — the OS read lives in the caller.
inline std::string normalize_ffi_version(std::uint32_t ms, std::uint32_t ls) {
    if (ms == 0 && ls == 0)
        return {};
    return format_file_version(ms, ls);
}

/// Crash/hang side: canonicalize an arbitrary version string (WER AppVersion, or
/// a re-canon of an agent-supplied value at the server) to EXACTLY the same
/// 4-group dotted quad `format_file_version` emits, so `(name, version)` joins
/// byte-for-byte across perf and stability. Contract:
///   - keep the leading run of dot-separated numeric groups (a trailing
///     non-numeric suffix like "10.0.0.0 (WinBuild…)" is dropped),
///   - normalize each group through an integer parse (no leading zeros: "01"->"1"),
///   - pad short forms with ".0" and cap at 4 groups ("3.2" -> "3.2.0.0"),
///   - an all-zero quad ("0.0.0.0") and an empty / non-numeric input both map to
///     "" — the single "unknown version" bucket,
///   - each group's digit run is capped (kMaxGroupDigits) so a hostile/garbage
///     AppVersion cannot produce an unbounded string on the wire or in the store.
/// A group whose value exceeds 0xffff (65535) cannot have come from a real
/// VS_FIXEDFILEINFO field, so it will legitimately never join a perf row — that
/// is a true cross-source difference, not a normalization defect; the value is
/// still normalized consistently here.
inline std::string canon_version(std::string_view raw) {
    constexpr std::size_t kMaxGroups = 4;
    constexpr std::size_t kMaxGroupDigits = 10; // a real version field is <= 5 digits; 10 caps garbage
    std::array<std::uint64_t, kMaxGroups> groups{};
    std::size_t ngroups = 0;
    bool all_zero = true;
    std::size_t i = 0;
    while (i < raw.size() && ngroups < kMaxGroups) {
        const std::size_t start = i;
        while (i < raw.size() && raw[i] >= '0' && raw[i] <= '9')
            ++i;
        if (i == start)
            break; // no digit where a group must start -> stop (drops any suffix)
        if (i - start > kMaxGroupDigits)
            break; // implausibly long numeric run -> stop parsing (garbage guard)
        std::uint64_t value = 0;
        std::from_chars(raw.data() + start, raw.data() + i, value); // bounded digits -> no overflow
        if (value != 0)
            all_zero = false;
        groups[ngroups++] = value;
        if (i < raw.size() && raw[i] == '.')
            ++i; // consume the separator and continue
        else
            break;
    }
    if (ngroups == 0 || all_zero)
        return {};
    std::string out;
    for (std::size_t k = 0; k < kMaxGroups; ++k) {
        if (k)
            out += '.';
        out += std::to_string(k < ngroups ? groups[k] : 0);
    }
    return out;
}

} // namespace yuzu::util
