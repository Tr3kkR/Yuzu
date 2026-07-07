/**
 * licensing_win.cpp — Windows detection surfaces for the license_scan plugin
 * (SLE roadmap §5 PR1 detection-surface table; ADR-0024 Decisions 2/11).
 *
 * Surfaces (probe_status tokens):
 *   slp_wmi         — WMI SoftwareLicensingProduct via the bounded enumerator
 *                     (C-8; never WBEM_INFINITE). Authoritative: OS/Office/MS
 *                     server licence status, channel, grace, evaluation end,
 *                     partial key.
 *   office_c2r      — HKLM ...\ClickToRun\Configuration (probable: C2R SKU →
 *                     subscription/volume/retail type).
 *   <ProbeSpec>     — machine-scope ProbeSpec table rows (sql_server,
 *                     exchange, visual_studio, autodesk_adsklicensing, veeam,
 *                     acronis, av_suites, vmware_workstation, winrar,
 *                     open_source_classification).
 *   per_user_hives  — user-scope ProbeSpec rows probed in each profile's
 *                     registry hive: loaded HKU\<SID> hives FIRST, offline
 *                     NTUSER.DAT via RegLoadKeyW only as fallback (roadmap
 *                     C-1 — clone of installed_apps' HiveUnloadGuard +
 *                     close-every-hive-HKEY-before-unload; the registry
 *                     plugin's manual-unload pattern is a known-broken
 *                     precedent, issue I-5). Reports `privilege_missing`
 *                     when SeBackup/SeRestore cannot be enabled (R15).
 *   per_user_files  — per-profile licence files (JetBrains
 *                     %APPDATA%-shaped .key paths, Adobe NGL sign-in
 *                     artefact), resolved via ProfileList — no hive needed.
 *
 * R17: every registry read goes through wide Reg*W APIs +
 * agents/shared/win_str.hpp (never the *A siblings).
 *
 * ADR-0024 D11 (binds the emission): per-user records carry
 * user_scope=user and user_ref=<local profile name>; when the profile name
 * cannot be resolved user_ref stays EMPTY — NEVER a SID. Deliberately does
 * NOT clone installed_apps' `username = sid` fallback.
 */

#ifdef _WIN32

#include "licensing_parsers.hpp"
#include "licensing_probes.hpp"
#include "licensing_record.hpp"
#include "licensing_wmi.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681, R17)

#include <cstdlib>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::license_scan {

namespace {

using yuzu::win::from_wide;
using yuzu::win::reg_sz_to_utf8;
using yuzu::win::to_wide;

// ── RAII registry helpers ───────────────────────────────────────────────────

// Closing every handle into a RegLoadKeyW-mounted hive BEFORE the unload is
// load-bearing: RegUnLoadKeyW fails ERROR_ACCESS_DENIED while any subtree
// handle is open (installed_apps_plugin.cpp:165-166 rule). All ProbeHost
// registry operations below open and close their HKEY within the call, so
// nothing outlives the mount.
struct HKeyCloser {
    HKEY h;
    explicit HKeyCloser(HKEY k) : h(k) {}
    ~HKeyCloser() {
        if (h)
            RegCloseKey(h);
    }
    HKeyCloser(const HKeyCloser&) = delete;
    HKeyCloser& operator=(const HKeyCloser&) = delete;
};

// RAII: unload the mounted hive on EVERY exit, including exceptions thrown
// mid-probe. A leaked mount is system-wide, survives process death, and
// locks the user's NTUSER.DAT until reboot (clone of
// installed_apps_plugin.cpp:676-683, roadmap C-1).
struct HiveUnloadGuard {
    const std::wstring& mount;
    ~HiveUnloadGuard() { RegUnLoadKeyW(HKEY_USERS, mount.c_str()); }
};

// ── ProbeHost with Reg*W registry access (R17) ─────────────────────────────

class WinRegProbeHost final : public ProbeHost {
public:
    /// Machine scope: HKLM, probing the 64-bit view first and falling back to
    /// the WoW6432Node view (32-bit-only installs like older vendor tools).
    WinRegProbeHost() : root_(HKEY_LOCAL_MACHINE), wow64_fallback_(true) {}

    /// User scope: a loaded HKU\<SID> hive or a RegLoadKeyW mount root. The
    /// caller owns `hive_root` and closes it before any unload.
    explicit WinRegProbeHost(HKEY hive_root) : root_(hive_root), wow64_fallback_(false) {}

    bool reg_key_exists(std::string_view key_path) override {
        HKEY h = open_key(key_path);
        if (!h)
            return false;
        RegCloseKey(h);
        return true;
    }

    std::optional<std::string> reg_read_str(std::string_view key_path,
                                            std::string_view value_name) override {
        HKEY h = open_key(key_path);
        if (!h)
            return std::nullopt;
        HKeyCloser guard{h};
        return read_str_value(h, value_name);
    }

    std::vector<std::string> reg_enum_subkeys(std::string_view key_path) override {
        std::vector<std::string> out;
        HKEY h = open_key(key_path);
        if (!h)
            return out;
        HKeyCloser guard{h};
        // RegEnumKeyExW's lpcchName is a WCHAR COUNT, not a byte size; bind
        // the buffer size and every reset to one constant (#1662 gotcha).
        constexpr DWORD kNameBufLen = 256;
        wchar_t name_buf[kNameBufLen]{};
        DWORD idx = 0;
        DWORD name_len = kNameBufLen;
        while (RegEnumKeyExW(h, idx++, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr) ==
               ERROR_SUCCESS) {
            out.push_back(from_wide(name_buf, static_cast<int>(name_len)));
            name_len = kNameBufLen;
        }
        return out;
    }

    std::vector<std::pair<std::string, std::string>>
    reg_enum_str_values(std::string_view key_path) override {
        std::vector<std::pair<std::string, std::string>> out;
        HKEY h = open_key(key_path);
        if (!h)
            return out;
        HKeyCloser guard{h};
        constexpr DWORD kNameBufLen = 512; // registry value names cap at 16383 wchars
        wchar_t name_buf[kNameBufLen]{};
        DWORD idx = 0;
        DWORD name_len = kNameBufLen;
        DWORD type = 0;
        while (RegEnumValueW(h, idx++, name_buf, &name_len, nullptr, &type, nullptr, nullptr) ==
               ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                std::string name = from_wide(name_buf, static_cast<int>(name_len));
                std::wstring wname(name_buf, name_len);
                if (auto value = read_str_value(h, wname))
                    out.emplace_back(std::move(name), std::move(*value));
            }
            name_len = kNameBufLen;
            type = 0;
        }
        return out;
    }

private:
    [[nodiscard]] HKEY open_key(std::string_view key_path) const {
        const std::wstring wpath = to_wide(key_path);
        HKEY h{};
        if (wow64_fallback_) {
            if (RegOpenKeyExW(root_, wpath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &h) ==
                ERROR_SUCCESS)
                return h;
            if (RegOpenKeyExW(root_, wpath.c_str(), 0, KEY_READ | KEY_WOW64_32KEY, &h) ==
                ERROR_SUCCESS)
                return h;
            return nullptr;
        }
        if (RegOpenKeyExW(root_, wpath.c_str(), 0, KEY_READ, &h) == ERROR_SUCCESS)
            return h;
        return nullptr;
    }

    static std::optional<std::string> read_str_value(HKEY h, std::string_view value_name) {
        return read_str_value(h, to_wide(value_name));
    }

    static std::optional<std::string> read_str_value(HKEY h, const std::wstring& wname) {
        DWORD type = 0;
        DWORD size = 0;
        if (RegQueryValueExW(h, wname.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
            return std::nullopt;
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || size == 0)
            return std::nullopt;
        std::vector<wchar_t> buf(size / sizeof(wchar_t) + 2, L'\0');
        DWORD size2 = static_cast<DWORD>(buf.size() * sizeof(wchar_t));
        if (RegQueryValueExW(h, wname.c_str(), nullptr, &type,
                             reinterpret_cast<LPBYTE>(buf.data()), &size2) != ERROR_SUCCESS)
            return std::nullopt;
        return reg_sz_to_utf8(buf.data(), size2);
    }

    HKEY root_;
    bool wow64_fallback_;
};

// ── slp_wmi (authoritative; surface table Windows row 1) ───────────────────

std::string row_get(const wmi::WmiRow& row, const char* key) {
    const auto it = row.find(key);
    return it == row.end() ? std::string{} : it->second;
}

void run_slp_surface(long long now_epoch, std::vector<LicRecord>& records,
                     std::vector<ProbeOutcome>& outcomes) {
    const auto result = wmi::query_software_licensing_products();
    if (!result.ok) {
        outcomes.push_back({"slp_wmi", false, 0, result.error});
        return;
    }

    std::size_t emitted = 0;
    for (const auto& row : result.rows) {
        const std::string partial_key = row_get(row, "PartialProductKey");
        const std::string status_raw = row_get(row, "LicenseStatus");
        const long status_code = status_raw.empty() ? -1 : std::strtol(status_raw.c_str(), nullptr, 10);
        // Only rows with a PartialProductKey or a meaningful (non-zero)
        // licence status — SLP carries ~100 keyless, never-activated SKU rows.
        if (partial_key.empty() && status_code <= 0)
            continue;

        LicRecord r;
        r.product = row_get(row, "Name");
        r.vendor = "Microsoft";
        r.status = status_raw.empty() ? "unknown" : slp_status_to_status(status_code);
        r.channel = classify_channel(row_get(row, "ProductKeyChannel"), row_get(row, "Description"));

        const std::string eval_end = parse_wmi_datetime_to_expiry(row_get(row, "EvaluationEndDate"));
        if (!eval_end.empty()) {
            r.license_type = "trial";
            r.expires_at = eval_end;
        } else if (r.channel == "kms" || r.channel == "mak") {
            r.license_type = "volume";
        } else if (r.channel == "oem") {
            r.license_type = "oem";
        } else if (r.channel == "retail") {
            r.license_type = "retail";
        } // else stays "unknown" — unknown-preserving, never guessed

        if (r.status == "grace") {
            // Countdown → ABSOLUTE midnight-epoch (D3 blob-stability): a
            // ticking minute counter must not change the record between syncs.
            const std::string grace_raw = row_get(row, "GracePeriodRemaining");
            const long long minutes = grace_raw.empty() ? 0 : std::strtoll(grace_raw.c_str(), nullptr, 10);
            const std::string until = grace_expiry_date(now_epoch, minutes);
            if (!until.empty())
                r.expires_at = until;
        }

        r.source = "os_licensing_api";
        r.confidence = "authoritative";
        r.key_hint = derive_key_hint(partial_key, ""); // OS partial key verbatim
        records.push_back(std::move(r));
        ++emitted;
    }

    if (result.truncated) {
        // The enumeration did not complete (C-8 row cap) — not a structural
        // success (ADR-0024 D3). Rows collected so far are still emitted for
        // diagnostics; the sync source decides skip semantics off this status.
        outcomes.push_back({"slp_wmi", false, emitted, "row_cap_exceeded"});
    } else {
        outcomes.push_back({"slp_wmi", true, emitted, {}});
    }
}

// ── office_c2r (probable; surface table Windows row 2) ─────────────────────

void run_office_c2r_surface(ProbeHost& host, std::vector<LicRecord>& records,
                            std::vector<ProbeOutcome>& outcomes) {
    static constexpr const char* kConfigKey =
        "SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration";
    std::size_t emitted = 0;
    if (host.reg_key_exists(kConfigKey)) {
        const std::string release_ids = host.reg_read_str(kConfigKey, "ProductReleaseIds").value_or("");
        const std::string version = host.reg_read_str(kConfigKey, "VersionToReport").value_or("");
        std::size_t pos = 0;
        while (pos <= release_ids.size() && !release_ids.empty()) {
            std::size_t comma = release_ids.find(',', pos);
            if (comma == std::string::npos)
                comma = release_ids.size();
            std::string token = release_ids.substr(pos, comma - pos);
            pos = comma + 1;
            while (!token.empty() && token.front() == ' ')
                token.erase(token.begin());
            while (!token.empty() && token.back() == ' ')
                token.pop_back();
            if (token.empty())
                continue;
            LicRecord r;
            r.product = "Microsoft Office (" + token + ")";
            r.vendor = "Microsoft";
            r.version = version;
            r.license_type = classify_office_release_id(token);
            r.status = "unknown"; // the C2R SKU says type, not licence state —
                                  // slp_wmi is the authoritative state source
            r.source = "registry_probe";
            r.confidence = "probable";
            r.exe_hints = "winword.exe,excel.exe,outlook.exe,powerpnt.exe";
            records.push_back(std::move(r));
            ++emitted;
            if (comma == release_ids.size())
                break;
        }
    }
    outcomes.push_back({"office_c2r", true, emitted, {}});
}

// ── per-user surfaces (C-1 hive mounting; R15 privileges; D11 user_ref) ────

struct ProfileEntry {
    std::string sid;
    std::string profile_name; // last path component; EMPTY when unresolvable —
                              // NEVER the SID (ADR-0024 D11)
    std::wstring profile_path_w; // expanded; empty when ProfileImagePath unreadable
};

std::vector<ProfileEntry> enumerate_profiles(std::string& error) {
    std::vector<ProfileEntry> out;
    static constexpr const char* kProfileListKey =
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

    HKEY profiles_key{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, to_wide(kProfileListKey).c_str(), 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS, &profiles_key) != ERROR_SUCCESS) {
        error = "profile_list_unreadable";
        return out;
    }
    HKeyCloser profiles_guard{profiles_key};

    constexpr DWORD kSidBufLen = 256;
    wchar_t sid_buf[kSidBufLen]{};
    DWORD idx = 0;
    DWORD sid_len = kSidBufLen; // WCHAR count, not bytes
    while (RegEnumKeyExW(profiles_key, idx++, sid_buf, &sid_len, nullptr, nullptr, nullptr,
                         nullptr) == ERROR_SUCCESS) {
        std::string sid = from_wide(sid_buf, static_cast<int>(sid_len));
        sid_len = kSidBufLen;

        // Skip system profiles (LocalSystem / LocalService / NetworkService).
        if (sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20")
            continue;

        ProfileEntry entry;
        entry.sid = sid;

        HKEY sid_key{};
        if (RegOpenKeyExW(profiles_key, to_wide(sid).c_str(), 0, KEY_READ, &sid_key) ==
            ERROR_SUCCESS) {
            HKeyCloser sid_guard{sid_key};
            wchar_t path_buf[512]{};
            DWORD path_size = sizeof(path_buf); // size in BYTES
            DWORD type = 0;
            if (RegQueryValueExW(sid_key, L"ProfileImagePath", nullptr, &type,
                                 reinterpret_cast<LPBYTE>(path_buf), &path_size) ==
                    ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ)) {
                size_t nch = path_size / sizeof(wchar_t);
                while (nch > 0 && path_buf[nch - 1] == L'\0')
                    --nch;
                std::wstring raw(path_buf, nch);
                // ProfileImagePath may be REG_EXPAND_SZ — expand once, here.
                wchar_t expanded[1024]{};
                if (ExpandEnvironmentStringsW(raw.c_str(), expanded, 1024) > 0)
                    entry.profile_path_w.assign(expanded);
                else
                    entry.profile_path_w = std::move(raw);
                const std::string path_utf8 =
                    from_wide(entry.profile_path_w.c_str(),
                              static_cast<int>(entry.profile_path_w.size()));
                const auto last_sep = path_utf8.find_last_of("\\/");
                if (last_sep != std::string::npos && last_sep + 1 < path_utf8.size())
                    entry.profile_name = path_utf8.substr(last_sep + 1);
            }
            // Unresolvable name → entry.profile_name stays EMPTY. The D11 SID
            // ban binds the emission: no `= sid` fallback here, ever.
        }
        out.push_back(std::move(entry));
    }
    return out;
}

/// Enable a token privilege the service account holds but which starts
/// disabled. RegLoadKeyW requires BOTH SeBackupPrivilege and
/// SeRestorePrivilege enabled (granted by scripts/install-agent-user.ps1:404-
/// 405; a hardened install may strip them — R15).
bool enable_privilege(const wchar_t* name) {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    bool ok = false;
    LUID luid{};
    if (LookupPrivilegeValueW(nullptr, name, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr) &&
            GetLastError() == ERROR_SUCCESS) {
            // ERROR_NOT_ALL_ASSIGNED means the privilege is absent from the
            // token entirely — AdjustTokenPrivileges "succeeds" but the
            // enable did not happen.
            ok = true;
        }
    }
    CloseHandle(token);
    return ok;
}

void stamp_user_records(std::vector<LicRecord>& records, std::size_t from,
                        const std::string& profile_name) {
    for (std::size_t i = from; i < records.size(); ++i) {
        records[i].user_scope = "user";
        records[i].user_ref = profile_name; // may be EMPTY — never a SID (D11)
    }
}

void per_user_file_probes(ProbeHost& fs_host, const std::string& profile_path_utf8,
                          std::vector<LicRecord>& out) {
    if (profile_path_utf8.empty())
        return;
    // JetBrains licence keys (roadmap: "%LOCALAPPDATA%-shaped per-profile
    // paths" — the .key files live under the profile's Roaming tree;
    // <Product>/eval/ keys are evaluations).
    static const ProbeSpec kJetbrainsSpec{"per_user_files", Platform::windows_os, Scope::user,
                                          ProbeKind::file_glob, "", jetbrains_key_interpreter(),
                                          nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
    for (const char* suffix :
         {"/AppData/Roaming/JetBrains/*/*.key", "/AppData/Roaming/JetBrains/*/eval/*.key"}) {
        for (const auto& match : fs_host.glob(profile_path_utf8 + suffix))
            kJetbrainsSpec.interpret(fs_host, kJetbrainsSpec, match, out);
    }
    // Adobe NGL sign-in artefact (Creative Cloud licensing state cache).
    const std::string opm = profile_path_utf8 + "\\AppData\\Local\\Adobe\\OOBE\\opm.db";
    if (fs_host.file_exists(opm)) {
        LicRecord r;
        r.product = "Adobe Creative Cloud";
        r.vendor = "Adobe";
        r.license_type = "subscription";
        r.status = "unknown"; // presence of the NGL artefact, not licence state
        r.source = "heuristic";
        r.confidence = "heuristic";
        out.push_back(std::move(r));
    }
}

void run_per_user_surfaces(std::vector<LicRecord>& records, std::vector<ProbeOutcome>& outcomes) {
    std::string enum_error;
    const auto profiles = enumerate_profiles(enum_error);
    if (!enum_error.empty()) {
        outcomes.push_back({"per_user_hives", false, 0, enum_error});
        outcomes.push_back({"per_user_files", false, 0, enum_error});
        return;
    }

    // R15: the offline-hive fallback rides SeBackupPrivilege/SeRestorePrivilege.
    const bool priv_ok =
        enable_privilege(L"SeBackupPrivilege") && enable_privilege(L"SeRestorePrivilege");

    WinRegProbeHost fs_host; // filesystem defaults only (per-user file probes)
    std::size_t hive_rows = 0;
    std::size_t file_rows = 0;

    for (const auto& profile : profiles) {
        // ── registry hive: loaded HKU\<SID> FIRST (C-1 probe order) ─────────
        std::size_t before = records.size();
        std::vector<ProbeOutcome> scratch; // aggregated into one surface below
        HKEY loaded{};
        if (RegOpenKeyExW(HKEY_USERS, to_wide(profile.sid).c_str(), 0, KEY_READ, &loaded) ==
            ERROR_SUCCESS) {
            HKeyCloser loaded_guard{loaded};
            WinRegProbeHost user_host{loaded};
            run_probe_specs(user_host, Platform::windows_os, Scope::user, records, scratch);
        } else if (priv_ok && !profile.profile_path_w.empty()) {
            // Offline fallback: mount NTUSER.DAT under a private name.
            const std::wstring ntuser = profile.profile_path_w + L"\\NTUSER.DAT";
            const std::wstring mount_w = to_wide("YUZU_LIC_" + profile.sid);
            if (RegLoadKeyW(HKEY_USERS, mount_w.c_str(), ntuser.c_str()) == ERROR_SUCCESS) {
                HiveUnloadGuard unload_guard{mount_w};
                {
                    HKEY mounted{};
                    if (RegOpenKeyExW(HKEY_USERS, mount_w.c_str(), 0, KEY_READ, &mounted) ==
                        ERROR_SUCCESS) {
                        HKeyCloser mounted_guard{mounted};
                        WinRegProbeHost user_host{mounted};
                        run_probe_specs(user_host, Platform::windows_os, Scope::user, records,
                                        scratch);
                    }
                } // every HKEY into the hive is closed HERE, before the
                  // unload guard runs (installed_apps :165-166 rule)
            }
            // A per-profile load failure (hive corrupt/locked) is not a
            // surface failure: per-user hives are never a primary surface
            // (ADR-0024 D3/R15) — the profile is skipped, the cycle proceeds.
        }
        stamp_user_records(records, before, profile.profile_name);
        hive_rows += records.size() - before;

        // ── profile licence files (no hive required) ───────────────────────
        before = records.size();
        const std::string profile_path_utf8 =
            profile.profile_path_w.empty()
                ? std::string{}
                : from_wide(profile.profile_path_w.c_str(),
                            static_cast<int>(profile.profile_path_w.size()));
        per_user_file_probes(fs_host, profile_path_utf8, records);
        stamp_user_records(records, before, profile.profile_name);
        file_rows += records.size() - before;
    }

    if (priv_ok) {
        outcomes.push_back({"per_user_hives", true, hive_rows, {}});
    } else {
        // R15: hardened installs that strip SeBackup/SeRestore surface as
        // privilege_missing through the live `surfaces` diagnostics. Loaded
        // hives were still probed (their records ride `list` regardless);
        // offline NTUSER.DAT hives were unreadable, so availability is
        // honestly degraded.
        outcomes.push_back({"per_user_hives", false, hive_rows, "privilege_missing"});
    }
    outcomes.push_back({"per_user_files", true, file_rows, {}});
}

} // namespace

// ── the Windows run ─────────────────────────────────────────────────────────

SurfaceRun run_platform_surfaces() {
    SurfaceRun run;
    WinRegProbeHost machine_host;

    // Authoritative first: SLP via the bounded WMI enumerator (C-8).
    run_slp_surface(machine_host.now_epoch(), run.records, run.outcomes);

    // Office ClickToRun configuration (probable).
    run_office_c2r_surface(machine_host, run.records, run.outcomes);

    // Machine-scope ProbeSpec rows (probable/heuristic).
    run_probe_specs(machine_host, Platform::windows_os, Scope::machine, run.records,
                    run.outcomes);

    // Per-user surfaces (ADR-0016 deviation, Decision 11; never primary).
    run_per_user_surfaces(run.records, run.outcomes);

    return run;
}

} // namespace yuzu::license_scan

#endif // _WIN32
