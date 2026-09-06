/**
 * autoruns_win.cpp — Windows leg of the autoruns plugin (P12).
 *
 * Implements yuzu::autoruns::collect_windows (autoruns_legs.hpp, P11):
 * HKLM Run/RunOnce/RunOnceEx (native + WOW6432Node views), Explorer
 * StartupApproved\{Run,Run32,StartupFolder} (system AND every reachable
 * per-user hive), Winlogon Shell/Userinit, AppInit_DLLs, Image File
 * Execution Options\*\Debugger, the common and per-user Startup folders,
 * Scheduled Tasks (ITaskService COM), and WMI permanent event subscriptions
 * (root\subscription). Per-user reads go through win_profiles.hpp's
 * with_user_hive ladder exclusively — no second offline-hive mount path,
 * and this file never enables a backup/restore privilege of its own.
 *
 * A1's the-rig probe (tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md,
 * 2026-09-06), Probe 3, quoted verbatim:
 *
 *   "MTA works for ITaskService on the-rig, in both the admin session and
 *   under LocalSystem -- the repo's agents/shared/win_com.hpp:33-35
 *   COINIT_MULTITHREADED choice is not a problem for ITaskService here;
 *   both apartment models gave identical HRESULTs and counts in each
 *   session."
 *
 * Consequently this file uses yuzu::shared::win::ComInit (COINIT_MULTITHREADED)
 * directly on the calling thread — no dedicated STA thread, no
 * bounded_wait.hpp join, is needed for the Task Scheduler walk. WMI already
 * gets its own bounded enumeration from run_bounded_wmi_query, independent
 * of the apartment question.
 *
 * ComInit::ok() intentionally does not expose the underlying HRESULT (only
 * a bool), so the one COM failure this file cannot render as a real
 * `hr_<hex>` token is CoInitializeEx itself failing -- reported as the fixed
 * sentinel `hr_cominit_failed` below. Every other COM/WMI failure in this
 * file (CoCreateInstance, Connect, GetFolder, GetTasks, and every
 * run_bounded_wmi_query call) carries the real HRESULT or the shared
 * wmi_bounded.hpp error token.
 *
 * Zero spawn primitives: every source here is a direct Win32/COM/WMI read.
 * schtasks.exe, wmic.exe and PowerShell are never invoked.
 *
 * WMI subscription rows are emitted one per __FilterToConsumerBinding,
 * joined against the enumerated __EventFilter/__EventConsumer rows by the
 * ref's Name (autoruns_win_wmi_join.hpp, P12 respec delta 1) -- a dangling
 * ref (matches no enumerated row) still emits its row and marks the source
 * `constrained|unresolved_ref` rather than collapsing N bindings into one
 * row or silently dropping the unresolved one.
 */

#include "autoruns_catalog.hpp"
#include "autoruns_legs.hpp"
#include "autoruns_parsers.hpp"

#include <yuzu/plugin.hpp>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <taskschd.h>

#include <win_com.hpp>
#include <win_profiles.hpp>
#include <win_reg_handle.hpp>
#include <wmi_bounded.hpp>

#include "autoruns_win_wmi_join.hpp"

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::autoruns {

namespace {

using yuzu::win::ReadValueStatus;
using yuzu::win::RegKey;

// ── small local helpers (pure; live here because autoruns_parsers.hpp is
//    P11's file and out of this package's scope) ─────────────────────────

/// `sources=` allow-list check (empty filter -> every source runs).
bool want(std::string_view filter, SourceId id) {
    if (filter.empty()) return true;
    const std::string_view id_str = source_id_string(id);
    std::size_t pos = 0;
    while (pos <= filter.size()) {
        const std::size_t comma = filter.find(',', pos);
        const std::string_view tok =
            comma == std::string_view::npos ? filter.substr(pos) : filter.substr(pos, comma - pos);
        if (tok == id_str) return true;
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return false;
}

/// Stable token for a non-ok ReadValueStatus -- fed into a source's
/// `constrained` reason, never dropped.
std::string_view read_status_token(ReadValueStatus st) {
    switch (st) {
    case ReadValueStatus::oversized:            return "oversized";
    case ReadValueStatus::malformed:            return "malformed";
    case ReadValueStatus::changed_during_read:  return "changed_during_read";
    case ReadValueStatus::not_found:            return "not_found";
    case ReadValueStatus::ok:                   return "ok";
    }
    return "ok";
}

std::string_view hive_status_token(yuzu::win::HiveAccessStatus st) {
    switch (st) {
    case yuzu::win::HiveAccessStatus::ok:                return "ok";
    case yuzu::win::HiveAccessStatus::not_found:         return "not_found";
    case yuzu::win::HiveAccessStatus::privilege_missing: return "privilege_missing";
    case yuzu::win::HiveAccessStatus::mount_failed:      return "mount_failed";
    }
    return "not_found";
}

/// Reverses user_profile_model.hpp's hex_encode (2 hex chars/byte, no
/// delimiter) -- needed because read_reg_value hex-encodes REG_BINARY into
/// `out_value` and the StartupApproved blob parser wants raw bytes.
std::vector<unsigned char> hex_decode(std::string_view hex) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}

std::int64_t filetime_to_unix(const FILETIME& ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    constexpr std::uint64_t kEpochDiff100ns = 116444736000000000ULL; // 1601 -> 1970
    if (uli.QuadPart < kEpochDiff100ns) return 0;
    return static_cast<std::int64_t>((uli.QuadPart - kEpochDiff100ns) / 10000000ULL);
}

std::int64_t reg_key_mtime(HKEY key) {
    FILETIME ft{};
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS)
        return filetime_to_unix(ft);
    return 0;
}

std::int64_t file_mtime(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
        return filetime_to_unix(data.ftLastWriteTime);
    return 0;
}

/// Minimal ISO-8601 "YYYY-MM-DDTHH:MM:SS[...]" -> Unix epoch seconds. A
/// trailing timezone offset (Task Scheduler's <Date> commonly carries one)
/// is ignored -- this is a best-effort mtime source for a row whose primary
/// timestamp signal (file/registry mtime) does not apply, not a validating
/// calendar parser. Returns 0 on anything that doesn't match the shape.
std::int64_t parse_iso8601_to_epoch(std::string_view s) {
    if (s.size() < 19) return 0;
    auto digit = [&](std::size_t i) -> int {
        if (i >= s.size() || s[i] < '0' || s[i] > '9') return -1;
        return s[i] - '0';
    };
    auto num = [&](std::size_t off, int width) -> int {
        int v = 0;
        for (int i = 0; i < width; ++i) {
            const int d = digit(off + static_cast<std::size_t>(i));
            if (d < 0) return -1;
            v = v * 10 + d;
        }
        return v;
    };
    if (s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != ' ') || s[13] != ':' ||
        s[16] != ':')
        return 0;
    const int year = num(0, 4);
    const int month = num(5, 2);
    const int day = num(8, 2);
    const int hour = num(11, 2);
    const int minute = num(14, 2);
    const int second = num(17, 2);
    if (year < 0 || month < 1 || month > 12 || day < 1 || day > 31 || hour < 0 || hour > 23 ||
        minute < 0 || minute > 59 || second < 0 || second > 60)
        return 0;

    // Howard Hinnant's days_from_civil (public domain), avoids any TZ-
    // dependent libc calendar call.
    int y = year;
    const unsigned m = static_cast<unsigned>(month);
    const unsigned d = static_cast<unsigned>(day);
    y -= (m <= 2) ? 1 : 0;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? static_cast<unsigned>(-3) : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days = era * 146097 + static_cast<std::int64_t>(doe) - 719468;
    return days * 86400 + hour * 3600 + minute * 60 + second;
}

std::string wstring_to_utf8(const std::wstring& ws) {
    return yuzu::win::from_wide(ws.c_str(), static_cast<int>(ws.size()));
}

std::wstring last_path_component(const std::wstring& path) {
    const auto pos = path.find_last_of(L'\\');
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

// ── generic row/source-outcome plumbing ──────────────────────────────────

struct SourceOutcome {
    std::vector<Row> rows;
    bool constrained = false;
    std::string reason; // first non-ok token seen; joined with ',' across profiles where relevant
};

void note_constraint(SourceOutcome& outcome, std::string_view token) {
    outcome.constrained = true;
    if (!outcome.reason.empty()) outcome.reason += ',';
    outcome.reason += token;
}

void finish_source(yuzu::CommandContext& ctx, SourceId id, const SourceOutcome& outcome) {
    for (const auto& r : outcome.rows) ctx.write_output(format_row(r));
    ctx.write_output(format_source_status(
        id, outcome.constrained ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED,
        outcome.rows.size(), outcome.constrained ? std::string_view{outcome.reason} : "ok"));
}

// ── 1. HKLM Run / RunOnce / RunOnceEx (native + WOW6432Node views) ───────

/// `key` must already be open (KEY_READ) -- this only enumerates+reads its
/// direct values, it never opens anything itself.
void collect_reg_values(HKEY key, const std::wstring& location, SourceId id, Scope scope,
                        std::string_view user, SourceOutcome& outcome) {
    auto names = yuzu::win::enumerate_value_names(key);
    if (!names.complete) note_constraint(outcome, "enumeration_incomplete");
    const std::int64_t mtime = reg_key_mtime(key);
    for (const auto& name : names.names) {
        std::string value, type_name;
        const auto st = yuzu::win::read_reg_value(key, name, value, type_name);
        if (st == ReadValueStatus::not_found) continue; // raced deletion; not a row

        Row row;
        row.source_id = id;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = wstring_to_utf8(location);
        row.entry = name;
        row.scope = scope;
        row.user = std::string{user};
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        if (st == ReadValueStatus::ok) {
            const auto split = split_command_line(value);
            row.target = split.target;
            row.args = split.args;
            row.enabled = Enabled::unknown; // Run/RunOnce carry no on/off bit of their own
        } else {
            row.enabled = Enabled::unmodelled;
            note_constraint(outcome, read_status_token(st));
        }
        outcome.rows.push_back(std::move(row));
    }
}

void open_and_collect(HKEY hive, const std::wstring& subkey, REGSAM extra_view, SourceId id,
                     const std::wstring& location, Scope scope, std::string_view user,
                     SourceOutcome& outcome) {
    RegKey key;
    if (RegOpenKeyExW(hive, subkey.c_str(), 0, KEY_READ | extra_view, key.put()) != ERROR_SUCCESS)
        return; // absent key on this host is not an error
    collect_reg_values(key.get(), location, id, scope, user, outcome);
}

void collect_hklm_run_family(std::string_view filter, SourceOutcome& run, SourceOutcome& runonce,
                             SourceOutcome& runonceex) {
    struct Entry {
        SourceId id;
        SourceOutcome* outcome;
        const wchar_t* subkey;
    };
    const Entry entries[] = {
        {SourceId::win_run_hklm, &run, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {SourceId::win_runonce_hklm, &runonce,
         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        // RunOnceEx's numbered-subkey nesting shape is not walked here --
        // only direct values under the key itself. Documented gap, same
        // spirit as the Startup-folder .lnk targets not being resolved.
        {SourceId::win_runonceex_hklm, &runonceex,
         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"},
    };
    for (const auto& e : entries) {
        if (!want(filter, e.id)) continue;
        const std::wstring native_loc = L"HKLM\\" + std::wstring{e.subkey};
        open_and_collect(HKEY_LOCAL_MACHINE, e.subkey, KEY_WOW64_64KEY, e.id, native_loc,
                         Scope::system, "-", *e.outcome);
        const std::wstring wow_loc = native_loc + L" [WOW6432Node]";
        open_and_collect(HKEY_LOCAL_MACHINE, e.subkey, KEY_WOW64_32KEY, e.id, wow_loc,
                         Scope::system, "-", *e.outcome);
    }
}

// ── 2. Explorer StartupApproved\{Run,Run32,StartupFolder} ────────────────

void collect_startup_approved_subkey(HKEY root, const wchar_t* subkey, const std::wstring& label,
                                     Scope scope, std::string_view user,
                                     std::map<std::string, bool>& seen, SourceOutcome& outcome) {
    RegKey key;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, key.put()) != ERROR_SUCCESS) return;
    auto names = yuzu::win::enumerate_value_names(key.get());
    if (!names.complete) note_constraint(outcome, "enumeration_incomplete");
    const std::int64_t mtime = reg_key_mtime(key.get());
    for (const auto& name : names.names) {
        if (seen.count(name)) continue; // joined by value name -- first subkey wins
        seen[name] = true;
        std::string value, type_name;
        const auto st = yuzu::win::read_reg_value(key.get(), name, value, type_name);
        if (st == ReadValueStatus::not_found) continue;

        Row row;
        row.source_id = SourceId::win_startup_approved;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = wstring_to_utf8(label);
        row.entry = name;
        row.scope = scope;
        row.user = std::string{user};
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        if (st == ReadValueStatus::ok) {
            const auto bytes = hex_decode(value);
            row.enabled = parse_startup_approved_blob(
                std::span<const unsigned char>(bytes.data(), bytes.size()));
        } else {
            row.enabled = Enabled::unmodelled;
            note_constraint(outcome, read_status_token(st));
        }
        outcome.rows.push_back(std::move(row));
    }
}

void collect_startup_approved_hive(HKEY root, const std::wstring& base_label, Scope scope,
                                   std::string_view user, SourceOutcome& outcome) {
    std::map<std::string, bool> seen;
    collect_startup_approved_subkey(
        root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
        base_label + L"\\Run", scope, user, seen, outcome);
    collect_startup_approved_subkey(
        root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32",
        base_label + L"\\Run32", scope, user, seen, outcome);
    collect_startup_approved_subkey(
        root,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder",
        base_label + L"\\StartupFolder", scope, user, seen, outcome);
}

// ── 3. Winlogon Shell / Userinit ─────────────────────────────────────────

void collect_winlogon(std::string_view filter, SourceOutcome& shell_out,
                     SourceOutcome& userinit_out) {
    struct Entry {
        SourceId id;
        SourceOutcome* outcome;
        const wchar_t* value_name;
        WinlogonValue (*parse)(std::string_view);
    };
    const Entry entries[] = {
        {SourceId::win_winlogon_shell, &shell_out, L"Shell", &parse_winlogon_shell},
        {SourceId::win_winlogon_userinit, &userinit_out, L"Userinit", &parse_winlogon_userinit},
    };
    RegKey key;
    const bool opened =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ,
                     key.put()) == ERROR_SUCCESS;
    const std::int64_t mtime = opened ? reg_key_mtime(key.get()) : 0;
    for (const auto& e : entries) {
        if (!want(filter, e.id)) continue;
        if (!opened) continue; // absent Winlogon key -> zero rows, not an error
        std::string value, type_name;
        const auto st = yuzu::win::read_reg_value(key.get(), yuzu::win::from_wide(e.value_name),
                                                  value, type_name);
        if (st == ReadValueStatus::not_found) continue;

        Row row;
        row.source_id = e.id;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
        row.entry = yuzu::win::from_wide(e.value_name);
        row.scope = Scope::system;
        row.user = "-";
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        if (st == ReadValueStatus::ok) {
            const auto parsed = e.parse(value);
            if (!parsed.entries.empty()) {
                row.target = parsed.entries.front();
                std::string extra;
                for (std::size_t i = 1; i < parsed.entries.size(); ++i) {
                    if (i > 1) extra += ',';
                    extra += parsed.entries[i];
                }
                row.args = extra;
            }
            row.enabled = Enabled::unknown; // no on/off state; target carries the real signal
        } else {
            row.enabled = Enabled::unmodelled;
            note_constraint(*e.outcome, read_status_token(st));
        }
        e.outcome->rows.push_back(std::move(row));
    }
}

// ── 4. AppInit_DLLs ───────────────────────────────────────────────────────

void collect_appinit_dlls(std::string_view filter, SourceOutcome& outcome) {
    if (!want(filter, SourceId::win_appinit_dlls)) return;
    RegKey key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_READ,
                      key.put()) != ERROR_SUCCESS)
        return;
    const std::int64_t mtime = reg_key_mtime(key.get());

    std::string load_value, load_type;
    const auto load_st = yuzu::win::read_reg_value(key.get(), "LoadAppInit_DLLs", load_value, load_type);
    Enabled toggle = Enabled::unknown;
    if (load_st == ReadValueStatus::ok) {
        toggle = (load_value == "0") ? Enabled::disabled : Enabled::enabled;
    } else if (load_st != ReadValueStatus::not_found) {
        note_constraint(outcome, read_status_token(load_st));
    }

    std::string dlls_value, dlls_type;
    const auto dlls_st = yuzu::win::read_reg_value(key.get(), "AppInit_DLLs", dlls_value, dlls_type);
    if (dlls_st == ReadValueStatus::not_found) return; // genuinely absent -- 0 rows, supported
    if (dlls_st != ReadValueStatus::ok) {
        note_constraint(outcome, read_status_token(dlls_st));
        Row row;
        row.source_id = SourceId::win_appinit_dlls;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
        row.entry = "AppInit_DLLs";
        row.enabled = Enabled::unmodelled;
        row.scope = Scope::system;
        row.user = "-";
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        outcome.rows.push_back(std::move(row));
        return;
    }
    for (const auto& dll : parse_appinit_dlls(dlls_value)) {
        Row row;
        row.source_id = SourceId::win_appinit_dlls;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
        row.entry = "AppInit_DLLs";
        row.target = dll;
        row.enabled = toggle;
        row.scope = Scope::system;
        row.user = "-";
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        outcome.rows.push_back(std::move(row));
    }
}

// ── 5. Image File Execution Options\*\Debugger ───────────────────────────

constexpr DWORD kMaxIfeoSubkeys = 4096;

void collect_ifeo(std::string_view filter, SourceOutcome& outcome) {
    if (!want(filter, SourceId::win_ifeo_debugger)) return;
    RegKey key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
                      L"Options",
                      0, KEY_READ, key.put()) != ERROR_SUCCESS)
        return;

    constexpr DWORD kNameBufLen = 512;
    wchar_t name_buf[kNameBufLen]{};
    DWORD idx = 0;
    DWORD name_len = kNameBufLen;
    while (idx < kMaxIfeoSubkeys &&
          RegEnumKeyExW(key.get(), idx, name_buf, &name_len, nullptr, nullptr, nullptr,
                       nullptr) == ERROR_SUCCESS) {
        const std::wstring exe_name_w(name_buf, name_len);
        const std::string exe_name = wstring_to_utf8(exe_name_w);
        ++idx;
        name_len = kNameBufLen;

        RegKey sub;
        if (RegOpenKeyExW(key.get(), exe_name_w.c_str(), 0, KEY_READ, sub.put()) != ERROR_SUCCESS)
            continue;
        std::string debugger_value, type_name;
        const auto st = yuzu::win::read_reg_value(sub.get(), "Debugger", debugger_value, type_name);
        if (st == ReadValueStatus::not_found) continue;

        Row row;
        row.source_id = SourceId::win_ifeo_debugger;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location =
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
            "Options\\" +
            exe_name;
        row.entry = exe_name;
        row.scope = Scope::system;
        row.user = "-";
        row.signed_state = Signed::not_checked;
        row.mtime = reg_key_mtime(sub.get());
        if (st == ReadValueStatus::ok) {
            const auto entry = parse_ifeo_debugger(exe_name, debugger_value);
            if (!entry.has_debugger) continue; // no override present -- not a persistence row
            row.target = entry.debugger;
            row.enabled = Enabled::enabled; // presence of a Debugger override is always active
        } else {
            row.enabled = Enabled::unmodelled;
            note_constraint(outcome, read_status_token(st));
        }
        outcome.rows.push_back(std::move(row));
    }
}

// ── 6. Startup folders (common + per-user) ───────────────────────────────

constexpr std::size_t kMaxStartupFolderEntries = 1024;

void collect_startup_folder(const std::wstring& dir, SourceId id, Scope scope,
                           std::string_view user, SourceOutcome& outcome) {
    WIN32_FIND_DATAW find_data{};
    const std::wstring pattern = dir + L"\\*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &find_data);
    if (h == INVALID_HANDLE_VALUE) return; // folder absent/unreadable -- zero rows, not an error
    std::size_t count = 0;
    do {
        const std::wstring name = find_data.cFileName;
        if (name == L"." || name == L"..") continue;
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (count >= kMaxStartupFolderEntries) {
            note_constraint(outcome, "row_cap");
            break;
        }
        Row row;
        row.source_id = id;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = wstring_to_utf8(dir);
        row.entry = wstring_to_utf8(name);
        // .lnk shell-link targets are not resolved -- target/args stay empty.
        row.enabled = Enabled::enabled; // presence in a Startup folder always runs at logon
        row.scope = scope;
        row.user = std::string{user};
        row.signed_state = Signed::not_checked;
        row.mtime = filetime_to_unix(find_data.ftLastWriteTime);
        outcome.rows.push_back(std::move(row));
        ++count;
    } while (FindNextFileW(h, &find_data));
    FindClose(h);
}

// ── 7. Scheduled Tasks (ITaskService) ────────────────────────────────────

constexpr std::size_t kMaxScheduledTasks = 10000;

std::string hr_token(HRESULT hr) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out = "hr_0x";
    for (int shift = 28; shift >= 0; shift -= 4)
        out += kHex[(static_cast<unsigned long>(hr) >> shift) & 0xF];
    return out;
}

void walk_task_folder(ITaskFolder* folder, SourceOutcome& outcome, std::size_t cap) {
    if (outcome.rows.size() >= cap) return;

    yuzu::shared::win::ComPtr<IRegisteredTaskCollection> tasks;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, tasks.put())) && tasks) {
        LONG count = 0;
        tasks->get_Count(&count);
        for (LONG i = 1; i <= count; ++i) {
            if (outcome.rows.size() >= cap) {
                note_constraint(outcome, "row_cap");
                return;
            }
            VARIANT idx;
            VariantInit(&idx);
            idx.vt = VT_I4;
            idx.lVal = i;
            yuzu::shared::win::ComPtr<IRegisteredTask> task;
            if (FAILED(tasks->get_Item(idx, task.put())) || !task) continue;

            BSTR path_b = nullptr;
            BSTR xml_b = nullptr;
            VARIANT_BOOL enabled_b = VARIANT_TRUE;
            task->get_Path(&path_b);
            task->get_Enabled(&enabled_b);
            task->get_Xml(&xml_b);
            const std::wstring path_w = path_b ? std::wstring(path_b, SysStringLen(path_b)) : L"";
            const std::wstring xml_w = xml_b ? std::wstring(xml_b, SysStringLen(xml_b)) : L"";
            if (path_b) SysFreeString(path_b);
            if (xml_b) SysFreeString(xml_b);

            const std::string xml_utf8 = wstring_to_utf8(xml_w);
            const auto info = parse_task_xml(xml_utf8);

            Row row;
            row.source_id = SourceId::win_scheduled_tasks;
            row.catalog_version = kAutorunSourceCatalogVersion;
            row.location = wstring_to_utf8(path_w);
            row.entry = wstring_to_utf8(last_path_component(path_w));
            row.target = info.command;
            row.args = info.arguments;
            row.enabled = (enabled_b == VARIANT_TRUE) ? Enabled::enabled : Enabled::disabled;
            row.scope = Scope::system;
            row.user = info.user_id.empty() ? "-" : info.user_id;
            row.signed_state = Signed::not_checked;

            std::size_t date_start = xml_utf8.find("<Date>");
            row.mtime = 0;
            if (date_start != std::string::npos) {
                date_start += 6;
                const std::size_t date_end = xml_utf8.find("</Date>", date_start);
                if (date_end != std::string::npos)
                    row.mtime =
                        parse_iso8601_to_epoch(std::string_view{xml_utf8}.substr(
                            date_start, date_end - date_start));
            }
            outcome.rows.push_back(std::move(row));
        }
    }

    yuzu::shared::win::ComPtr<ITaskFolderCollection> subfolders;
    if (SUCCEEDED(folder->GetFolders(0, subfolders.put())) && subfolders) {
        LONG count = 0;
        subfolders->get_Count(&count);
        for (LONG i = 1; i <= count && outcome.rows.size() < cap; ++i) {
            VARIANT idx;
            VariantInit(&idx);
            idx.vt = VT_I4;
            idx.lVal = i;
            yuzu::shared::win::ComPtr<ITaskFolder> sub;
            if (FAILED(subfolders->get_Item(idx, sub.put())) || !sub) continue;
            walk_task_folder(sub.get(), outcome, cap);
        }
    }
}

void collect_scheduled_tasks(std::string_view filter, SourceOutcome& outcome) {
    if (!want(filter, SourceId::win_scheduled_tasks)) return;

    yuzu::shared::win::ComInit com;
    if (!com.ok()) {
        // ComInit::ok() does not surface the real HRESULT -- see file banner.
        note_constraint(outcome, "hr_cominit_failed");
        return;
    }

    yuzu::shared::win::ComPtr<ITaskService> service;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_ITaskService, reinterpret_cast<void**>(service.put()));
    if (FAILED(hr) || !service) {
        note_constraint(outcome, hr_token(hr));
        return;
    }

    VARIANT empty;
    VariantInit(&empty);
    hr = service->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) {
        note_constraint(outcome, hr_token(hr));
        return;
    }

    yuzu::shared::win::ComPtr<ITaskFolder> root;
    yuzu::shared::win::BStr root_path(L"\\");
    hr = service->GetFolder(root_path.get(), root.put());
    if (FAILED(hr) || !root) {
        note_constraint(outcome, hr_token(hr));
        return;
    }

    walk_task_folder(root.get(), outcome, kMaxScheduledTasks);
}

// ── 8. WMI permanent event subscriptions ─────────────────────────────────

std::string format_wmi_block(std::string_view cim_class, const yuzu::shared::wmi::WmiRow& row) {
    std::string out = "CimClass : ";
    out += cim_class;
    out += '\n';
    for (const auto& [k, v] : row) {
        out += k;
        out += " : ";
        out += v;
        out += '\n';
    }
    out += '\n';
    return out;
}

// Formats one joined binding's three CIM blocks (only THIS binding's filter,
// consumer, and the binding itself -- never the whole enumeration) and
// parses them as a self-contained triple. The consumer block keeps its real
// CIM class when the matched row carries one (`CimClass`, as a live COM
// query's synthesized value or a captured PowerShell one already has);
// otherwise it falls back to the generic `__EventConsumer` label -- either
// way `parse_wmi_subscription_triple` routes it by the substring `Consumer`.
WmiTriple parse_joined_binding(const yuzu::autoruns::WmiJoinedBinding& joined) {
    std::string combined = format_wmi_block("__EventFilter", joined.filter);
    const auto class_it = joined.consumer.find("CimClass");
    const std::string consumer_class =
        class_it != joined.consumer.end() && !class_it->second.empty() ? class_it->second
                                                                        : "__EventConsumer";
    combined += format_wmi_block(consumer_class, joined.consumer);
    combined += format_wmi_block("__FilterToConsumerBinding", joined.binding);
    return parse_wmi_subscription_triple(combined);
}

void collect_wmi_subscriptions(std::string_view filter, SourceOutcome& outcome) {
    if (!want(filter, SourceId::win_wmi_subscriptions)) return;

    const yuzu::shared::wmi::BoundedQueryOptions opts; // defaults; never WBEM_INFINITE
    auto filters =
        yuzu::shared::wmi::run_bounded_wmi_query(L"root\\subscription", L"SELECT * FROM __EventFilter", opts);
    auto consumers = yuzu::shared::wmi::run_bounded_wmi_query(
        L"root\\subscription", L"SELECT * FROM __EventConsumer", opts);
    auto bindings = yuzu::shared::wmi::run_bounded_wmi_query(
        L"root\\subscription", L"SELECT * FROM __FilterToConsumerBinding", opts);

    for (const auto* r : {&filters, &consumers, &bindings}) {
        if (r->error) {
            note_constraint(outcome, *r->error);
            return;
        }
    }
    const bool truncated = filters.truncated || consumers.truncated || bindings.truncated;

    // One row per binding, joined on the Filter/Consumer CIM reference Name
    // -- N bindings must never collapse into one row (P12 respec delta 1).
    const auto joined =
        yuzu::autoruns::join_wmi_bindings(filters.rows, consumers.rows, bindings.rows);
    bool noted_unresolved_ref = false;
    for (const auto& binding : joined) {
        const auto triple = parse_joined_binding(binding);

        Row row;
        row.source_id = SourceId::win_wmi_subscriptions;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = "root\\subscription";
        if (!triple.filter_name.empty()) {
            row.entry = triple.filter_name;
        } else if (!triple.consumer_name.empty()) {
            row.entry = triple.consumer_name;
        } else {
            // Dangling ref: neither side resolved to an enumerated row. A
            // forensic reader must still see the raw reference, never a
            // dropped row.
            const auto filter_ref = binding.binding.find("Filter");
            const auto consumer_ref = binding.binding.find("Consumer");
            if (filter_ref != binding.binding.end()) row.entry = filter_ref->second;
            else if (consumer_ref != binding.binding.end()) row.entry = consumer_ref->second;
        }
        row.target = triple.target;
        row.args = triple.query;
        row.enabled = Enabled::unknown; // no on/off bit on a WMI subscription
        row.scope = Scope::system;
        row.user = "-";
        row.signed_state = Signed::not_checked;
        row.mtime = 0; // no timestamp exposed by these three CIM classes
        outcome.rows.push_back(std::move(row));

        if ((!binding.filter_matched || !binding.consumer_matched) && !noted_unresolved_ref) {
            note_constraint(outcome, "unresolved_ref");
            noted_unresolved_ref = true;
        }
    }
    if (truncated) note_constraint(outcome, "row_cap");
}

} // namespace

// ── entry point ───────────────────────────────────────────────────────────

int collect_windows(yuzu::CommandContext& ctx, std::string_view filter) {
    SourceOutcome run_hklm, runonce_hklm, runonceex_hklm;
    collect_hklm_run_family(filter, run_hklm, runonce_hklm, runonceex_hklm);

    SourceOutcome run_hku, runonce_hku;
    SourceOutcome startup_approved;
    if (want(filter, SourceId::win_startup_approved))
        collect_startup_approved_hive(HKEY_LOCAL_MACHINE, L"HKLM", Scope::system, "-",
                                     startup_approved);

    SourceOutcome winlogon_shell, winlogon_userinit;
    collect_winlogon(filter, winlogon_shell, winlogon_userinit);

    SourceOutcome appinit;
    collect_appinit_dlls(filter, appinit);

    SourceOutcome ifeo;
    collect_ifeo(filter, ifeo);

    SourceOutcome startup_folder_common, startup_folder_user;
    if (want(filter, SourceId::win_startup_folder_common)) {
        wchar_t program_data[MAX_PATH]{};
        const DWORD n = GetEnvironmentVariableW(L"ProgramData", program_data, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            const std::wstring dir =
                std::wstring(program_data) + L"\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp";
            collect_startup_folder(dir, SourceId::win_startup_folder_common, Scope::system, "-",
                                   startup_folder_common);
        }
    }

    SourceOutcome scheduled_tasks;
    collect_scheduled_tasks(filter, scheduled_tasks);

    SourceOutcome wmi_subscriptions;
    collect_wmi_subscriptions(filter, wmi_subscriptions);

    // ── per-user pass: ProfileList + every reachable HKU hive ────────────
    const bool need_per_user = want(filter, SourceId::win_run_hku) ||
                               want(filter, SourceId::win_runonce_hku) ||
                               want(filter, SourceId::win_startup_approved) ||
                               want(filter, SourceId::win_startup_folder_user);
    if (need_per_user) {
        bool profiles_ok = false;
        bool profiles_truncated = false;
        const auto records =
            yuzu::win::enumerate_profile_records(profiles_ok, &profiles_truncated);
        if (profiles_truncated)
            ctx.write_output(yuzu::profiles::render_profile_list_truncated_warning(
                yuzu::win::kMaxProfiles));

        if (!profiles_ok) {
            for (SourceOutcome* o : {&run_hku, &runonce_hku, &startup_approved,
                                     &startup_folder_user})
                note_constraint(*o, "profile_list_unreadable");
        } else {
            const auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
            const auto profiles = yuzu::profiles::build_profile_list(records, hku_subkeys);

            for (const auto& profile : profiles) {
                const std::string_view user =
                    profile.profile_name.empty() ? std::string_view{profile.sid}
                                                 : std::string_view{profile.profile_name};

                if (want(filter, SourceId::win_startup_folder_user) &&
                    !profile.profile_path.empty()) {
                    const std::wstring dir = yuzu::win::to_wide(profile.profile_path) +
                                            L"\\AppData\\Roaming\\Microsoft\\Windows\\Start "
                                            L"Menu\\Programs\\Startup";
                    collect_startup_folder(dir, SourceId::win_startup_folder_user, Scope::user,
                                          user, startup_folder_user);
                }

                if (!want(filter, SourceId::win_run_hku) &&
                    !want(filter, SourceId::win_runonce_hku) &&
                    !want(filter, SourceId::win_startup_approved))
                    continue;

                yuzu::win::HiveAccessReport report;
                const auto status = yuzu::win::with_user_hive(
                    profile.sid, profile.profile_path,
                    [&](HKEY root) {
                        if (want(filter, SourceId::win_run_hku))
                            open_and_collect(root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                            0, SourceId::win_run_hku,
                                            L"HKU\\" + yuzu::win::to_wide(profile.sid) + L"\\Run",
                                            Scope::user, user, run_hku);
                        if (want(filter, SourceId::win_runonce_hku))
                            open_and_collect(
                                root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0,
                                SourceId::win_runonce_hku,
                                L"HKU\\" + yuzu::win::to_wide(profile.sid) + L"\\RunOnce",
                                Scope::user, user, runonce_hku);
                        if (want(filter, SourceId::win_startup_approved))
                            collect_startup_approved_hive(
                                root, L"HKU\\" + yuzu::win::to_wide(profile.sid), Scope::user,
                                user, startup_approved);
                    },
                    &report);

                for (const auto& line : yuzu::profiles::render_hive_access_lines(
                         status, report.unload_failed, report.mount_name, profile.sid))
                    ctx.write_output(line); // unload_failed warnings surfaced, never dropped

                if (status != yuzu::win::HiveAccessStatus::ok) {
                    const std::string token =
                        profile.sid + ":" + std::string{hive_status_token(status)};
                    if (want(filter, SourceId::win_run_hku)) note_constraint(run_hku, token);
                    if (want(filter, SourceId::win_runonce_hku))
                        note_constraint(runonce_hku, token);
                    if (want(filter, SourceId::win_startup_approved))
                        note_constraint(startup_approved, token);
                }
            }
        }
    }

    if (want(filter, SourceId::win_run_hklm)) finish_source(ctx, SourceId::win_run_hklm, run_hklm);
    if (want(filter, SourceId::win_runonce_hklm))
        finish_source(ctx, SourceId::win_runonce_hklm, runonce_hklm);
    if (want(filter, SourceId::win_runonceex_hklm))
        finish_source(ctx, SourceId::win_runonceex_hklm, runonceex_hklm);
    if (want(filter, SourceId::win_run_hku)) finish_source(ctx, SourceId::win_run_hku, run_hku);
    if (want(filter, SourceId::win_runonce_hku))
        finish_source(ctx, SourceId::win_runonce_hku, runonce_hku);
    if (want(filter, SourceId::win_startup_approved))
        finish_source(ctx, SourceId::win_startup_approved, startup_approved);
    if (want(filter, SourceId::win_winlogon_shell))
        finish_source(ctx, SourceId::win_winlogon_shell, winlogon_shell);
    if (want(filter, SourceId::win_winlogon_userinit))
        finish_source(ctx, SourceId::win_winlogon_userinit, winlogon_userinit);
    if (want(filter, SourceId::win_appinit_dlls))
        finish_source(ctx, SourceId::win_appinit_dlls, appinit);
    if (want(filter, SourceId::win_ifeo_debugger))
        finish_source(ctx, SourceId::win_ifeo_debugger, ifeo);
    if (want(filter, SourceId::win_startup_folder_common))
        finish_source(ctx, SourceId::win_startup_folder_common, startup_folder_common);
    if (want(filter, SourceId::win_startup_folder_user))
        finish_source(ctx, SourceId::win_startup_folder_user, startup_folder_user);
    if (want(filter, SourceId::win_scheduled_tasks))
        finish_source(ctx, SourceId::win_scheduled_tasks, scheduled_tasks);
    if (want(filter, SourceId::win_wmi_subscriptions))
        finish_source(ctx, SourceId::win_wmi_subscriptions, wmi_subscriptions);

    return 0;
}

} // namespace yuzu::autoruns

#endif // _WIN32
