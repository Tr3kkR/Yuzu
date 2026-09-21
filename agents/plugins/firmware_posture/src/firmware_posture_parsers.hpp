/**
 * firmware_posture_parsers.hpp -- pure decoders, row mappers and decisions for the
 * firmware_posture plugin (firmware vendor, version and update-pending posture). No OS header,
 * no I/O, nothing throws on malformed input: each per-OS leg only performs the read and hands
 * bytes / strings / maps to the functions here (tests/unit/test_firmware_posture_parsers.cpp).
 *
 * Rows: firmware|<field>|<value>|<source>, source in smbios wmi dmi fwupd iokit sysctl, every
 * field via yuzu::util::safe_output_field. Value states that are not data: `absent` (the OS
 * definitively reports nothing; no failure token, status stays OK), `unreadable` (the read
 * failed; always paired with a failure token and a non-OK status), `unavailable` (the mechanism
 * is not installed, e.g. no fwupd; not a failure), and `unmodelled=` on fwupd devices (flag bits
 * this mapper does not name). Failure tokens are `<source>:<detail>`.
 */
#pragma once

#include <yuzu/plugin.h>         // YuzuResultStatus / Completeness (plain C enums)
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

#include <constraint_accumulator.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::firmware_posture {

inline constexpr std::string_view kSrcSmbios = "smbios";
inline constexpr std::string_view kSrcWmi = "wmi";
inline constexpr std::string_view kSrcDmi = "dmi";
inline constexpr std::string_view kSrcFwupd = "fwupd";
inline constexpr std::string_view kSrcIokit = "iokit";
inline constexpr std::string_view kSrcSysctl = "sysctl";

inline constexpr std::string_view kAbsent = "absent";
inline constexpr std::string_view kUnreadable = "unreadable";
inline constexpr std::string_view kUnavailable = "unavailable";

/// A firmware fact plus its read state: `value` = data; else `unreadable` = the read failed,
/// otherwise the OS reported nothing (absent).
struct Field {
    std::optional<std::string> value;
    bool unreadable = false;
};

struct FirmwareRow {
    std::string field;
    std::string value;
    std::string source;
};

/// firmware|<field>|<value>|<source>; no trailing newline (write_output separates rows).
[[nodiscard]] inline std::string format_row(const FirmwareRow& r) {
    return "firmware|" + yuzu::util::safe_output_field(r.field) + '|' +
           yuzu::util::safe_output_field(r.value) + '|' + yuzu::util::safe_output_field(r.source);
}

/// The catch-all row the shared execute() emits (frozen-seam containment).
[[nodiscard]] inline std::string format_internal_error_row() { return "constrained|internal_error"; }

[[nodiscard]] inline FirmwareRow field_row(std::string_view field, const Field& f,
                                           std::string_view source) {
    std::string v = f.value && !f.value->empty()
                        ? *f.value
                        : std::string{f.unreadable ? kUnreadable : kAbsent};
    return {std::string{field}, std::move(v), std::string{source}};
}

enum class ReadOutcome { ok, absent, denied, failed };

/// POSIX errno numbers as plain integers (stable on Linux and macOS): ENOENT/ENOTDIR = the
/// file definitively is not there; EACCES/EPERM = refused; anything else failed.
[[nodiscard]] constexpr ReadOutcome classify_errno(int e) noexcept {
    if (e == 0) return ReadOutcome::ok;
    if (e == 2 || e == 20) return ReadOutcome::absent;  // ENOENT, ENOTDIR
    if (e == 1 || e == 13) return ReadOutcome::denied;  // EPERM, EACCES
    return ReadOutcome::failed;
}

/// Win32 error numbers (the Windows TU static_asserts them against winerror.h): 2/3 not found,
/// 5 access denied.
[[nodiscard]] constexpr ReadOutcome classify_win32_error(std::uint32_t e) noexcept {
    if (e == 0) return ReadOutcome::ok;
    if (e == 2 || e == 3) return ReadOutcome::absent; // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
    if (e == 5) return ReadOutcome::denied;           // ERROR_ACCESS_DENIED
    return ReadOutcome::failed;
}

/// WMI / COM HRESULT bit patterns: WBEM_E_ACCESS_DENIED / E_ACCESSDENIED are refusals; a
/// missing namespace, class or object (0x8004100E, 0x80041010, 0x80041002) is absence.
[[nodiscard]] constexpr ReadOutcome classify_hresult(std::uint32_t hr) noexcept {
    if (hr == 0) return ReadOutcome::ok;
    if (hr == 0x80041003u || hr == 0x80070005u) return ReadOutcome::denied;
    if (hr == 0x8004100Eu || hr == 0x80041010u || hr == 0x80041002u) return ReadOutcome::absent;
    return ReadOutcome::failed;
}

/// Everything a leg gathered: rows to write plus the failure accounting.
struct FirmwareReport {
    std::vector<FirmwareRow> rows;
    yuzu::shared::ConstraintAccumulator constraints;
    bool denied = false; // at least one read was REFUSED (not merely failed)

    void add(FirmwareRow r) { rows.push_back(std::move(r)); }
    void add(std::string_view field, std::string_view value, std::string_view source) {
        rows.push_back({std::string{field}, std::string{value}, std::string{source}});
    }
    void add_all(std::vector<FirmwareRow> rs) {
        for (auto& r : rs) rows.push_back(std::move(r));
    }
    /// A failed read: an `unreadable` row (never `absent`), the token, and the denial flag.
    void fail(std::string_view field, std::string_view source, std::string_view token,
              bool was_denied = false) {
        rows.push_back({std::string{field}, std::string{kUnreadable}, std::string{source}});
        constraints.add_failure(token);
        denied = denied || was_denied;
    }
    /// A token with no row of its own (the row for it was already emitted by a mapper).
    void note_failure(std::string_view token, bool was_denied = false) {
        constraints.add_failure(token);
        denied = denied || was_denied;
    }
};

struct Verdict {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    std::string reason;
    int rc;
};

/// No failure token: OK / FULL / rc 0 (absent and unavailable rows do NOT count as failures).
/// Any failure token: PERMISSION_DENIED when a read was refused, else CONSTRAINED; PARTIAL
/// with every token joined; rc 1.
[[nodiscard]] inline Verdict select_verdict(const yuzu::shared::ConstraintAccumulator& acc,
                                            bool denied) {
    if (!acc.any_failure())
        return {YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, std::string{}, 0};
    return {denied ? YUZU_RESULT_STATUS_PERMISSION_DENIED : YUZU_RESULT_STATUS_CONSTRAINED,
            YUZU_RESULT_COMPLETENESS_PARTIAL, acc.reason(), 1};
}

namespace detail {

inline bool all_digits(std::string_view s) noexcept {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

inline std::string rtrim(std::string_view s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' ||
                          s.back() == '\r' || s.back() == '\0'))
        s.remove_suffix(1);
    return std::string{s};
}

inline std::optional<unsigned> to_uint(std::string_view s) noexcept {
    if (!all_digits(s) || s.size() > 9) return std::nullopt;
    unsigned v = 0;
    for (char c : s) v = v * 10 + static_cast<unsigned>(c - '0');
    return v;
}

inline constexpr std::size_t kRsmbHeader = 8; // Used20CallingMethod, Major, Minor, Dmi, u32 Length

inline std::uint32_t le32(std::span<const std::uint8_t> b, std::size_t o) noexcept {
    return static_cast<std::uint32_t>(b[o]) | static_cast<std::uint32_t>(b[o + 1]) << 8 |
           static_cast<std::uint32_t>(b[o + 2]) << 16 | static_cast<std::uint32_t>(b[o + 3]) << 24;
}
inline std::uint16_t le16(std::span<const std::uint8_t> b, std::size_t o) noexcept {
    return static_cast<std::uint16_t>(b[o] | b[o + 1] << 8);
}

/// 1-based SMBIOS string index into the string-set at [start, end) (end = one past the final
/// double NUL). nullopt = index runs past the set (malformed).
inline std::optional<std::string> smbios_string(std::span<const std::uint8_t> t, std::size_t start,
                                                std::size_t end, unsigned idx) {
    std::size_t p = start;
    for (unsigned i = 1;; ++i) {
        if (p >= end || t[p] == 0) return std::nullopt; // ran out of strings
        std::size_t q = p;
        while (q < end && t[q] != 0) ++q;
        if (i == idx) {
            return rtrim(std::string_view{reinterpret_cast<const char*>(t.data() + p), q - p});
        }
        p = q + 1;
    }
}

inline std::string clean_component(std::string_view s) { // keep `;`/`=` out of the composite
    std::string o = rtrim(s);
    for (char& c : o) if (c == ';' || c == '=') c = ',';
    return o;
}
inline std::optional<std::uint64_t> parse_u64(std::string_view s) noexcept {
    if (!all_digits(s) || s.size() > 20) return std::nullopt;
    std::uint64_t v = 0;
    for (char c : s) {
        const unsigned d = static_cast<unsigned>(c - '0');
        if (v > (UINT64_MAX - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}

/// Trimmed non-empty text at `key`, else no value.
inline Field text_field(const std::map<std::string, std::string>& m, const char* key) {
    Field f;
    if (auto it = m.find(key); it != m.end())
        if (std::string v = rtrim(it->second); !v.empty()) f.value = std::move(v);
    return f;
}

} // namespace detail

/// One release-date shape across sources: SMBIOS/DMI `MM/DD/YYYY` and a WMI CIM datetime
/// `YYYYMMDDhhmmss.mmmmmm+UUU` both become `YYYY-MM-DD`. Anything else (SMBIOS also permits
/// a 2-digit year, and hosts emit free text) is returned unchanged rather than guessed at.
[[nodiscard]] inline std::string normalize_release_date(std::string_view raw) {
    const std::string s = detail::rtrim(raw);
    // MM/DD/YYYY
    if (s.size() == 10 && s[2] == '/' && s[5] == '/' && detail::all_digits(s.substr(0, 2)) &&
        detail::all_digits(s.substr(3, 2)) && detail::all_digits(s.substr(6, 4)))
        return s.substr(6, 4) + '-' + s.substr(0, 2) + '-' + s.substr(3, 2);
    // CIM datetime: 14 digits, '.', 6 digits, sign, 3 digits
    if (s.size() == 25 && detail::all_digits(std::string_view{s}.substr(0, 14)) && s[14] == '.' &&
        (s[21] == '+' || s[21] == '-'))
        return s.substr(0, 4) + '-' + s.substr(4, 2) + '-' + s.substr(6, 2);
    return s;
}

/// A release-date field with its value normalised.
[[nodiscard]] inline FirmwareRow date_row(Field f, std::string_view source) {
    if (f.value) f.value = normalize_release_date(*f.value);
    return field_row("release_date", f, source);
}

struct Smbios0 {
    Field vendor, version, release_date;
    std::optional<std::uint64_t> rom_size_bytes;
    std::optional<unsigned> bios_major, bios_minor; // System BIOS Major/Minor Release
    std::optional<unsigned> ec_major, ec_minor;     // Embedded Controller Firmware Release
};

struct Smbios0Result {
    bool constrained = false; // true: `token` says why and `data` must not be trusted
    std::string token;        // smbios:truncated | smbios:malformed | smbios:no_type0
    Smbios0 data;
};

/// Parses the first type-0 structure of an RSMB blob as GetSystemFirmwareTable('RSMB') returns
/// it (8-byte RawSMBIOSData header, then the structure table). Bounds-checked at every step:
/// a blob shorter than the header's own Length claim, a structure or string-set running past
/// the end, or a malformed structure all return `constrained` with a token; nothing throws.
[[nodiscard]] inline Smbios0Result parse_smbios_type0(std::span<const std::uint8_t> raw) {
    using detail::le16;
    using detail::le32;
    Smbios0Result res;
    auto bad = [&](std::string_view tok) {
        res.constrained = true;
        res.token = std::string{tok};
        res.data = {};
        return res;
    };
    if (raw.size() < detail::kRsmbHeader) return bad("smbios:truncated");
    const std::uint32_t claimed = le32(raw, 4);
    if (raw.size() - detail::kRsmbHeader < claimed) return bad("smbios:truncated");
    const auto t = raw.subspan(detail::kRsmbHeader, claimed);

    std::size_t off = 0;
    while (off < t.size()) {
        if (t.size() - off < 4) return bad("smbios:truncated");
        const std::uint8_t type = t[off];
        const std::size_t len = t[off + 1];
        if (len < 4) return bad("smbios:malformed");
        if (t.size() - off < len) return bad("smbios:truncated");
        const std::size_t sstart = off + len;
        // String-set: NUL-terminated strings ended by one extra NUL (two NULs when empty).
        std::size_t p = sstart;
        for (;; ++p) {
            if (p + 1 >= t.size()) return bad("smbios:truncated");
            if (t[p] == 0 && t[p + 1] == 0) break;
        }
        const std::size_t send = p + 2;
        if (type == 127) return bad("smbios:no_type0"); // end-of-table before any type 0
        if (type != 0) {
            off = send;
            continue;
        }
        if (len < 0x12) return bad("smbios:malformed");
        Smbios0 d;
        auto str = [&](std::size_t at, Field& f) {
            const unsigned idx = t[off + at];
            if (idx == 0) return true; // no string: absent
            auto s = detail::smbios_string(t, sstart, send, idx);
            if (!s) return false;
            if (!s->empty()) f.value = std::move(*s);
            return true;
        };
        if (!str(4, d.vendor) || !str(5, d.version) || !str(8, d.release_date))
            return bad("smbios:malformed");
        const unsigned rom = t[off + 9];
        if (rom != 0xFF) {
            d.rom_size_bytes = static_cast<std::uint64_t>(rom + 1) * 64ull * 1024ull;
        } else if (len >= 0x1A) { // SMBIOS 3.1+: Extended BIOS ROM Size, bits 15:14 = unit
            const std::uint16_t ext = le16(t, off + 0x18);
            const unsigned unit = ext >> 14;
            const std::uint64_t n = ext & 0x3FFFu;
            if (unit == 0) d.rom_size_bytes = n * 1024ull * 1024ull;
            else if (unit == 1) d.rom_size_bytes = n * 1024ull * 1024ull * 1024ull;
            // units 2/3 are reserved: leave unset (unmodelled, not guessed)
        }
        if (len >= 0x18) { // SMBIOS 2.4+: 0xFF in a release byte = not specified
            auto rel = [&](std::size_t at) -> std::optional<unsigned> {
                const unsigned v = t[off + at];
                return v == 0xFF ? std::nullopt : std::optional<unsigned>{v};
            };
            d.bios_major = rel(0x14);
            d.bios_minor = rel(0x15);
            d.ec_major = rel(0x16);
            d.ec_minor = rel(0x17);
        }
        res.data = std::move(d);
        return res;
    }
    return bad("smbios:no_type0");
}

/// vendor/version/release_date always (absent when no string); the rest only when specified.
inline void add_release(std::vector<FirmwareRow>& out, const char* field, std::optional<unsigned> major,
                        std::optional<unsigned> minor, std::string_view source) {
    if (major && minor)
        out.push_back({field, std::to_string(*major) + '.' + std::to_string(*minor), std::string{source}});
}

[[nodiscard]] inline std::vector<FirmwareRow> smbios_rows(const Smbios0& d,
                                                          std::string_view source = kSrcSmbios) {
    std::vector<FirmwareRow> out;
    out.push_back(field_row("vendor", d.vendor, source));
    out.push_back(field_row("version", d.version, source));
    out.push_back(date_row(d.release_date, source));
    if (d.rom_size_bytes)
        out.push_back({"rom_size_bytes", std::to_string(*d.rom_size_bytes), std::string{source}});
    add_release(out, "bios_release", d.bios_major, d.bios_minor, source);
    add_release(out, "ec_release", d.ec_major, d.ec_minor, source);
    return out;
}

struct DmiInfo {
    Field vendor, version, release_date;
    std::optional<unsigned> bios_major, bios_minor;
    bool release_malformed = false; // bios_release present but not `<n>.<n>`: token dmi:bios_release
};

/// `files` maps a /sys/class/dmi/id file name (bios_vendor, bios_version, bios_date,
/// bios_release) to its raw content, trailing newline included; a key not in the map was
/// absent, unless the leg lists it in `unreadable_keys` (a refused/failed read).
[[nodiscard]] inline DmiInfo parse_dmi_sysfs(const std::map<std::string, std::string>& files,
                                             const std::vector<std::string>& unreadable_keys = {}) {
    DmiInfo d;
    auto pick = [&](const char* key, Field& f) {
        f = detail::text_field(files, key);
        f.unreadable = std::find(unreadable_keys.begin(), unreadable_keys.end(), key) != unreadable_keys.end();
    };
    pick("bios_vendor", d.vendor);
    pick("bios_version", d.version);
    pick("bios_date", d.release_date);
    auto it = files.find("bios_release");
    if (it != files.end()) {
        const std::string v = detail::rtrim(it->second);
        const auto dot = v.find('.');
        std::optional<unsigned> maj, min;
        if (dot != std::string::npos) {
            maj = detail::to_uint(std::string_view{v}.substr(0, dot));
            min = detail::to_uint(std::string_view{v}.substr(dot + 1));
        }
        if (maj && min) {
            d.bios_major = maj;
            d.bios_minor = min;
        } else if (!v.empty()) {
            d.release_malformed = true;
        }
    }
    return d;
}

[[nodiscard]] inline std::vector<FirmwareRow> dmi_rows(const DmiInfo& d) {
    std::vector<FirmwareRow> out;
    out.push_back(field_row("vendor", d.vendor, kSrcDmi));
    out.push_back(field_row("version", d.version, kSrcDmi));
    out.push_back(date_row(d.release_date, kSrcDmi));
    add_release(out, "bios_release", d.bios_major, d.bios_minor, kSrcDmi);
    return out;
}

using WmiRow = std::map<std::string, std::string>; // same type as yuzu::shared::wmi::WmiRow

/// Manufacturer -> vendor, SMBIOSBIOSVersion -> version, ReleaseDate (CIM datetime) -> release_date.
[[nodiscard]] inline std::vector<FirmwareRow> wmi_bios_rows(const WmiRow& row) {
    return {field_row("vendor", detail::text_field(row, "Manufacturer"), kSrcWmi),
            field_row("version", detail::text_field(row, "SMBIOSBIOSVersion"), kSrcWmi),
            date_row(detail::text_field(row, "ReleaseDate"), kSrcWmi)};
}

enum class FwupdOutcome { unavailable, no_devices, denied, failed };

/// Classifies a failed D-Bus call by error name (empty = the bus itself failed to open, judged
/// by errno): daemon not installed/activatable = `unavailable` (a state, not a failure),
/// `NothingToDo` = reachable daemon with no devices, a refusal = `denied`, else `failed`.
[[nodiscard]] inline FwupdOutcome classify_fwupd_error(std::string_view dbus_error_name,
                                                       int err) noexcept {
    if (dbus_error_name == "org.freedesktop.DBus.Error.ServiceUnknown" ||
        dbus_error_name == "org.freedesktop.DBus.Error.NameHasNoOwner")
        return FwupdOutcome::unavailable;
    if (dbus_error_name == "org.freedesktop.fwupd.NothingToDo") return FwupdOutcome::no_devices;
    if (dbus_error_name == "org.freedesktop.DBus.Error.AccessDenied" ||
        dbus_error_name == "org.freedesktop.fwupd.PermissionDenied")
        return FwupdOutcome::denied;
    if (dbus_error_name.empty()) { // e.g. a container without the system bus socket
        const auto o = classify_errno(err);
        if (o != ReadOutcome::failed && o != ReadOutcome::ok)
            return o == ReadOutcome::absent ? FwupdOutcome::unavailable : FwupdOutcome::denied;
    }
    return FwupdOutcome::failed;
}

/// FwupdDeviceFlags (fwupd-enums.h, uint64). Bits 0..19 are named here; a device carrying any
/// bit above them is reported `unmodelled` rather than having that bit silently dropped.
inline constexpr std::uint64_t kFwupdUpdatable = 1ull << 1;
inline constexpr std::uint64_t kFwupdNeedsReboot = 1ull << 8;
inline constexpr std::uint64_t kFwupdModelledMask = (1ull << 20) - 1;
inline constexpr std::size_t kMaxFwupdDevices = 256;

/// Keys (string values): DeviceId, Name, Version, Flags (decimal uint64), optionally HasUpgrades
/// ("true"/"false": GetUpgrades returned a release or not; absent = not asked). One map per
/// `a{sv}` device in the GetDevices reply.
using FwupdDevice = std::map<std::string, std::string>;

struct FwupdRows {
    std::vector<FirmwareRow> rows;
    std::vector<std::string> failures; // fwupd:shape | fwupd:row_cap
    std::string update_pending;        // yes | no | unknown (aggregate over updatable devices)
};

/// One `fwupd_device` row per device. A device missing DeviceId or carrying a non-numeric
/// Flags is malformed: no row for it, a `fwupd:shape` failure instead (never a partial row).
[[nodiscard]] inline FwupdRows fwupd_device_rows(const std::vector<FwupdDevice>& devices) {
    FwupdRows out;
    bool any_yes = false, any_unknown = false;
    std::size_t n = 0;
    for (const auto& dev : devices) {
        if (n++ == kMaxFwupdDevices) {
            out.failures.push_back("fwupd:row_cap");
            break;
        }
        auto get = [&](const char* k) -> std::optional<std::string> {
            auto it = dev.find(k);
            if (it == dev.end()) return std::nullopt;
            return it->second;
        };
        const auto id = get("DeviceId");
        const auto flags = get("Flags") ? detail::parse_u64(*get("Flags")) : std::nullopt;
        if (!id || id->empty() || !flags) {
            out.failures.push_back("fwupd:shape");
            continue;
        }
        const bool updatable = (*flags & kFwupdUpdatable) != 0;
        const bool reboot = (*flags & kFwupdNeedsReboot) != 0;
        const bool unknown = (*flags & ~kFwupdModelledMask) != 0;
        std::string pending = "unknown";
        if (auto h = get("HasUpgrades")) pending = (*h == "true") ? "yes" : (*h == "false" ? "no" : "unknown");
        if (updatable) {
            any_yes = any_yes || pending == "yes";
            any_unknown = any_unknown || pending == "unknown";
        }
        auto name = get("Name");
        auto ver = get("Version");
        std::string v = "id=" + detail::clean_component(*id) +
                        ";name=" + (name && !name->empty() ? detail::clean_component(*name) : std::string{kAbsent}) +
                        ";version=" + (ver && !ver->empty() ? detail::clean_component(*ver) : std::string{kAbsent}) +
                        ";updatable=" + (updatable ? "yes" : "no") +
                        ";needs_reboot=" + (reboot ? "yes" : "no") + ";update_pending=" + pending +
                        ";unmodelled=" + (unknown ? "yes" : "no");
        out.rows.push_back({"fwupd_device", std::move(v), std::string{kSrcFwupd}});
    }
    out.update_pending = any_yes ? "yes" : (any_unknown ? "unknown" : "no");
    out.rows.push_back({"update_pending", out.update_pending, std::string{kSrcFwupd}});
    return out;
}

/// fwupd is not installed / not on the bus: a state, not a failure.
[[nodiscard]] inline FirmwareRow fwupd_unavailable_row() {
    return {"update_pending", std::string{kUnavailable}, std::string{kSrcFwupd}};
}

struct DtNode { // one IODeviceTree node; a node that does not exist is a default DtNode
    std::map<std::string, std::string> props; // properties that decoded to text
    std::vector<std::string> undecodable;     // present but not text (wrong type / binary)
};

/// A device-tree property is OSData holding text, NUL-terminated and often NUL-padded (the
/// `firmware-version` property is a 256-byte buffer). Text = leading printable bytes then only
/// NULs; anything else (embedded binary) is not text and returns nullopt. Empty text is nullopt.
[[nodiscard]] inline std::optional<std::string> decode_dt_string(std::span<const std::uint8_t> b) {
    std::size_t n = 0;
    while (n < b.size() && b[n] != 0) {
        if (b[n] < 0x20 || b[n] == 0x7F) return std::nullopt;
        ++n;
    }
    for (std::size_t i = n; i < b.size(); ++i)
        if (b[i] != 0) return std::nullopt;
    if (n == 0) return std::nullopt;
    return std::string(reinterpret_cast<const char*>(b.data()), n);
}

inline constexpr std::string_view kDtRom = "IODeviceTree:/rom";
inline constexpr std::string_view kDtChosen = "IODeviceTree:/chosen";
inline constexpr std::string_view kDtRoot = "IODeviceTree:/";

struct MacosSelection {
    Field vendor, version, release_date;
    std::string version_source; // "<node>#<key>" that carried the version, or "absent"
};

/// Intel (`/rom`: version, release-date, vendor) is preferred; Apple Silicon has no `/rom`, its
/// firmware version is `/chosen` `system-firmware-version` (else `firmware-version`) and its
/// vendor is the device-tree root `manufacturer`. A key that exists but did not decode as text
/// makes that field `unreadable`, never `absent`.
[[nodiscard]] inline MacosSelection select_macos_firmware(const DtNode& rom, const DtNode& chosen,
                                                          const DtNode& root) {
    MacosSelection s;
    s.version_source = std::string{kAbsent};
    auto has = [](const std::vector<std::string>& v, const char* k) {
        return std::find(v.begin(), v.end(), k) != v.end();
    };
    auto take = [&](Field& f, const DtNode& n, const char* key) {
        if (f.value) return;
        auto it = n.props.find(key);
        if (it != n.props.end()) f.value = it->second;
        else if (has(n.undecodable, key)) f.unreadable = true;
    };
    struct Src { const DtNode* n; std::string_view path; const char* key; };
    for (const Src& c : {Src{&rom, kDtRom, "version"}, Src{&chosen, kDtChosen, "system-firmware-version"},
                         Src{&chosen, kDtChosen, "firmware-version"}}) {
        take(s.version, *c.n, c.key);
        if (s.version.value) {
            s.version_source = std::string{c.path} + '#' + c.key;
            s.version.unreadable = false;
            break;
        }
    }
    take(s.release_date, rom, "release-date");
    take(s.vendor, rom, "vendor");
    take(s.vendor, root, "manufacturer");
    if (s.vendor.value) s.vendor.unreadable = false;
    if (s.release_date.value) s.release_date.unreadable = false;
    return s;
}

[[nodiscard]] inline std::vector<FirmwareRow> macos_rows(const MacosSelection& s,
                                                         const Field& hw_model) {
    std::vector<FirmwareRow> out;
    out.push_back(field_row("vendor", s.vendor, kSrcIokit));
    out.push_back(field_row("version", s.version, kSrcIokit));
    out.push_back(date_row(s.release_date, kSrcIokit));
    out.push_back({"version_source", s.version_source, std::string{kSrcIokit}});
    out.push_back(field_row("model", hw_model, kSrcSysctl));
    return out;
}

} // namespace yuzu::firmware_posture
