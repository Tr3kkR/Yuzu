#pragma once

/**
 * system_hardening_win_parsers.hpp -- pure decoders for the Windows leg of the
 * system_hardening plugin (system_hardening_win.cpp). No <windows.h>, no OS
 * call, no I/O; unit-tested on every OS (test_system_hardening_win_parsers.cpp).
 *
 * 1. HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel values
 *    `MitigationOptions` / `MitigationAuditOptions` (REG_BINARY, documented
 *    16/24 bytes = 2/3 little-endian QWORDs). The FIRST QWORD follows the
 *    PROCESS_CREATION_MITIGATION_POLICY_* layout of <winbase.h>: nibble n
 *    holds bits [4n, 4n+3]. Two-bit policies (nibble >= 2): 0 default, 1 on,
 *    2 off, 3 = per-policy meaning (reserved/opt-out/audit) -> `unmodelled`.
 *    Nibble 0 holds three 1-bit flags (bit0 DEP, bit1 DEP ATL thunk, bit2
 *    SEHOP): set reads `on`, clear reads `default`. Later QWORDs are beyond
 *    the documented table: one row, `unmodelled` when non-zero.
 *    That the registry value reuses this layout is CONFIRMED ONLY by the
 *    the-rig capture recorded in the fixture's .provenance.txt; until that
 *    fixture lands the fixture test fails loudly instead of skipping.
 * 2. The agent's own GetProcessMitigationPolicy `Flags` DWORD
 *    (decode_self_policy): effective policy, on/off only.
 *
 * ROW: posture|windows|<policy>|<raw>|<state>, state in {on, off, default,
 * unmodelled, absent, unreadable}. `absent` = the OS says it does not exist;
 * `unreadable` = the read failed. Never one token for both. <raw> is "-" when
 * nothing was read (absent/unreadable), matching system_hardening_parsers.hpp.
 * Never throws (bad_alloc aside); fallible functions return std::expected.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::system_hardening::mitigation {

enum class PolicyState { on, off, default_state, unmodelled };

constexpr std::string_view state_token(PolicyState s) {
    switch (s) {
    case PolicyState::on:
        return "on";
    case PolicyState::off:
        return "off";
    case PolicyState::default_state:
        return "default";
    case PolicyState::unmodelled:
        return "unmodelled";
    }
    return "unmodelled";
}

struct MitigationRow {
    std::string policy; // e.g. "mitigation.dep"
    std::string raw;    // "0x<hex>" -- the nibble/bit/flags value that produced `state`
    PolicyState state{PolicyState::unmodelled};
};

struct DecodeError {
    std::string token; // empty_blob | odd_length | not_qword_aligned | oversized |
                       // no_hex_digits | odd_hex_digits | bad_hex
};

template <class T>
using Result = std::expected<T, DecodeError>;

/// Documented value is 16/24 bytes; anything past this is not that value.
inline constexpr std::size_t kMaxBlobBytes = 256;

/// All fields are machine tokens (never OS free text): no escaping needed.
inline std::string format_posture_row(std::string_view policy, std::string_view raw,
                                      std::string_view state) {
    std::string out = "posture|windows|";
    out += policy;
    out += '|';
    out += raw;
    out += '|';
    out += state;
    return out;
}

inline std::string format_posture_row(const MitigationRow& r) {
    return format_posture_row(r.policy, r.raw, state_token(r.state));
}

namespace detail {

enum class Kind { flag_bit, two_bit };

struct PolicyDef {
    std::string_view name;
    uint8_t nibble;      // nibble index within the first QWORD (0..15)
    uint8_t bit;         // Kind::flag_bit only: bit within the nibble
    Kind kind;
};

// Source: PROCESS_CREATION_MITIGATION_POLICY_* in <winbase.h>; nibble 1 is undefined.
inline constexpr std::array<PolicyDef, 17> kPolicyTable{{
    {"dep", 0, 0, Kind::flag_bit},                          // DEP_ENABLE            0x01
    {"dep_atl_thunk", 0, 1, Kind::flag_bit},                // DEP_ATL_THUNK_ENABLE  0x02
    {"sehop", 0, 2, Kind::flag_bit},                        // SEHOP_ENABLE          0x04
    {"force_relocate_images", 2, 0, Kind::two_bit},         // << 8
    {"heap_terminate", 3, 0, Kind::two_bit},                // << 12
    {"aslr_bottom_up", 4, 0, Kind::two_bit},                // << 16
    {"aslr_high_entropy", 5, 0, Kind::two_bit},             // << 20
    {"strict_handle_checks", 6, 0, Kind::two_bit},          // << 24
    {"win32k_system_call_disable", 7, 0, Kind::two_bit},    // << 28
    {"extension_point_disable", 8, 0, Kind::two_bit},       // << 32
    {"prohibit_dynamic_code", 9, 0, Kind::two_bit},         // << 36
    {"cfg", 10, 0, Kind::two_bit},                          // << 40
    {"block_non_microsoft_binaries", 11, 0, Kind::two_bit}, // << 44
    {"font_disable", 12, 0, Kind::two_bit},                 // << 48
    {"image_load_no_remote", 13, 0, Kind::two_bit},         // << 52
    {"image_load_no_low_label", 14, 0, Kind::two_bit},      // << 56
    {"image_load_prefer_system32", 15, 0, Kind::two_bit},   // << 60
}};

inline std::string hex_of(uint64_t v, int min_digits = 1) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string digits;
    do {
        digits.insert(digits.begin(), kHex[v & 0xF]);
        v >>= 4;
    } while (v != 0);
    while (static_cast<int>(digits.size()) < min_digits)
        digits.insert(digits.begin(), '0');
    return "0x" + digits;
}

inline uint64_t le_qword(std::span<const uint8_t> in, std::size_t qword_index) {
    uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(in[qword_index * 8 + i]) << (8 * i);
    return v;
}

} // namespace detail

/// Decodes one MitigationOptions/MitigationAuditOptions blob; `prefix` starts
/// every policy name. A 0-byte, odd-length or non-QWORD-multiple blob is a
/// DecodeError, never a partial decode.
inline Result<std::vector<MitigationRow>> decode_mitigation_options(std::span<const uint8_t> blob,
                                                                    std::string_view prefix) {
    if (blob.empty())
        return std::unexpected(DecodeError{"empty_blob"});
    if (blob.size() % 2 != 0)
        return std::unexpected(DecodeError{"odd_length"});
    if (blob.size() > kMaxBlobBytes)
        return std::unexpected(DecodeError{"oversized"});
    if (blob.size() % 8 != 0)
        return std::unexpected(DecodeError{"not_qword_aligned"});

    const uint64_t q0 = detail::le_qword(blob, 0);
    std::vector<MitigationRow> rows;

    for (const auto& def : detail::kPolicyTable) {
        const auto nib = static_cast<uint8_t>((q0 >> (4 * def.nibble)) & 0xF);
        MitigationRow row;
        row.policy = std::string{prefix} + std::string{def.name};
        if (def.kind == detail::Kind::flag_bit) {
            const uint8_t bit = (nib >> def.bit) & 1;
            row.raw = detail::hex_of(bit);
            row.state = bit ? PolicyState::on : PolicyState::default_state;
        } else {
            row.raw = detail::hex_of(nib);
            switch (nib) {
            case 0:
                row.state = PolicyState::default_state;
                break;
            case 1:
                row.state = PolicyState::on;
                break;
            case 2:
                row.state = PolicyState::off;
                break;
            default: // 3: per-policy meaning (reserved / opt-out / audit) -- not modelled
                row.state = PolicyState::unmodelled;
                break;
            }
        }
        rows.push_back(std::move(row));
    }

    // Undefined bits in QWORD 0: nibble 1, bit 3 of nibble 0.
    if (const auto n1 = static_cast<uint8_t>((q0 >> 4) & 0xF); n1 != 0)
        rows.push_back({std::string{prefix} + "reserved_n1", detail::hex_of(n1),
                        PolicyState::unmodelled});
    if (const auto b3 = static_cast<uint8_t>((q0 >> 3) & 1); b3 != 0)
        rows.push_back({std::string{prefix} + "reserved_n0_bit3", detail::hex_of(b3),
                        PolicyState::unmodelled});

    // QWORDs beyond the table.
    for (std::size_t q = 1; q < blob.size() / 8; ++q) {
        const uint64_t v = detail::le_qword(blob, q);
        rows.push_back({std::string{prefix} + "ext_q" + std::to_string(q),
                        detail::hex_of(v, 16),
                        v == 0 ? PolicyState::default_state : PolicyState::unmodelled});
    }
    return rows;
}

/// Which GetProcessMitigationPolicy structure the `Flags` DWORD came from.
enum class SelfPolicy { dep, aslr, cfg };

/// Decodes a PROCESS_MITIGATION_{DEP,ASLR,CONTROL_FLOW_GUARD}_POLICY `Flags`
/// DWORD (<winnt.h> layouts) into `self.*` rows; `raw` = Flags in decimal.
inline std::vector<MitigationRow> decode_self_policy(SelfPolicy which, uint32_t flags) {
    struct Bit {
        std::string_view name;
        uint8_t bit;
    };
    std::vector<Bit> bits;
    switch (which) {
    case SelfPolicy::dep:
        bits = {{"self.dep", 0}}; // Enable; bit1 (DisableAtlThunkEmulation) is not a posture claim
        break;
    case SelfPolicy::aslr:
        bits = {{"self.aslr_bottom_up", 0},
                {"self.aslr_force_relocate", 1},
                {"self.aslr_high_entropy", 2}};
        break;
    case SelfPolicy::cfg:
        bits = {{"self.cfg", 0}, {"self.cfg_export_suppression", 1}, {"self.cfg_strict_mode", 2}};
        break;
    }
    std::vector<MitigationRow> rows;
    for (const auto& b : bits)
        rows.push_back({std::string{b.name}, std::to_string(flags),
                        ((flags >> b.bit) & 1u) ? PolicyState::on : PolicyState::off});
    return rows;
}

/// Hex text -> bytes. Accepts bare hex (whitespace, optional "0x") or a
/// `reg query` line ("    MitigationOptions    REG_BINARY    0022...").
inline Result<std::vector<uint8_t>> parse_hex_blob(std::string_view text) {
    if (const auto pos = text.find("REG_BINARY"); pos != std::string_view::npos) {
        text.remove_prefix(pos + std::string_view{"REG_BINARY"}.size());
        if (const auto nl = text.find('\n'); nl != std::string_view::npos)
            text = text.substr(0, nl);
    }
    std::vector<uint8_t> out;
    int pending = -1;
    bool any = false;
    auto is_space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    std::size_t i = 0;
    while (i < text.size() && is_space(text[i]))
        ++i;
    if (i + 1 < text.size() && text[i] == '0' && (text[i + 1] == 'x' || text[i + 1] == 'X'))
        i += 2;
    for (; i < text.size(); ++i) {
        const char c = text[i];
        if (is_space(c))
            continue;
        int v = -1;
        if (c >= '0' && c <= '9')
            v = c - '0';
        else if (c >= 'a' && c <= 'f')
            v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            v = c - 'A' + 10;
        if (v < 0)
            return std::unexpected(DecodeError{"bad_hex"});
        any = true;
        if (pending < 0) {
            pending = v;
        } else {
            out.push_back(static_cast<uint8_t>((pending << 4) | v));
            pending = -1;
        }
    }
    if (!any)
        return std::unexpected(DecodeError{"no_hex_digits"});
    if (pending >= 0)
        return std::unexpected(DecodeError{"odd_hex_digits"});
    return out;
}

} // namespace yuzu::system_hardening::mitigation
