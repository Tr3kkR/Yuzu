// win_profiles.hpp -- Win32 shell for user-profile / registry-hive discovery
// (PR1.7). Gathers raw ProfileList rows and HKEY_USERS subkey names into the
// plain structs user_profile_model.hpp classifies; every decision lives
// there -- this file is mechanical Reg*W plumbing only, deliberately kept
// free of branching logic so it stays thin.
//
// Ported from (not re-derived from) license_scan's licensing_win.cpp -- the
// governance-hardened reference for this exact ladder (ADR-0024, roadmap
// C-1/R15/R17) -- and specifically NOT from registry_plugin.cpp's
// do_get_user_value, which licensing_win.cpp's own header comment names as a
// known-broken precedent (issue I-5): it hard-codes
// C:\Users\<username>\NTUSER.DAT instead of reading ProfileImagePath, never
// enables SeBackup/SeRestore despite its own comment saying they are
// required, and its ERROR_SHARING_VIOLATION branch reads the mount point
// even when nothing was mounted there.
//
// R17: every registry read goes through wide Reg*W APIs + win_str.hpp
// (never the *A siblings).
//
// Windows-only by construction (#ifdef _WIN32); the header is empty
// elsewhere.

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "user_profile_model.hpp"
#include "win_reg_handle.hpp"
#include "win_str.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace yuzu::win {

/// Bounds on the profile walk. registry_plugin.cpp's original get_value
/// sized a value buffer from a RegQueryValueExW call whose return code was
/// ignored, then allocated unbounded -- these two caps replace that with an
/// explicit ceiling.
inline constexpr std::size_t kMaxProfiles = 512;
inline constexpr DWORD kMaxRegValueBytes = 1u * 1024u * 1024u; // 1 MiB

// Two-pass ExpandEnvironmentStringsW. The single-pass form SILENTLY
// TRUNCATES: on overflow the API does not fail -- it returns the required
// wchar count (including the terminating NUL), which a bare `> 0` test reads
// as success, so an over-long ProfileImagePath yields a valid-LOOKING but
// wrong path. Pass 1 sizes (dest=nullptr, size=0); pass 2 fills. Returns
// `in` unchanged if the API fails, or if the environment grew between the
// two calls -- an unexpanded literal is a VISIBLY wrong path, never a
// plausible-but-wrong one.
inline std::wstring expand_env_strings(const std::wstring& in) {
    const DWORD needed = ExpandEnvironmentStringsW(in.c_str(), nullptr, 0);
    if (needed == 0)
        return in;
    std::wstring buf(needed, L'\0'); // `needed` INCLUDES the terminating NUL
    const DWORD written = ExpandEnvironmentStringsW(in.c_str(), buf.data(), needed);
    if (written == 0 || written > needed)
        return in;
    buf.resize(written - 1); // drop the NUL from the string's size
    return buf;
}

// Reads HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList,
// returning one RawProfileRecord per subkey (SID) found, capped at
// kMaxProfiles, with ProfileImagePath already environment-expanded. `ok` is
// set false only when the ProfileList key itself could not be opened -- a
// per-profile ProfileImagePath read failure is reported as an empty
// profile_image_path on that one record, never a dropped record. `truncated`,
// if non-null, is set true when the cap was reached -- a caller that cares
// about completeness (list_profiles) surfaces this; one that's looking up a
// single profile (get_user_value) may pass nullptr and ignore it.
inline std::vector<yuzu::profiles::RawProfileRecord> enumerate_profile_records(
    bool& ok, bool* truncated = nullptr) {
    std::vector<yuzu::profiles::RawProfileRecord> out;
    ok = false;
    if (truncated)
        *truncated = false;

    RegKey profiles;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS, profiles.put()) != ERROR_SUCCESS)
        return out;
    ok = true;

    constexpr DWORD kSidBufLen = 256; // WCHAR count, not bytes
    wchar_t sid_buf[kSidBufLen]{};
    DWORD idx = 0;
    DWORD sid_len = kSidBufLen;
    while (out.size() < kMaxProfiles &&
           RegEnumKeyExW(profiles.get(), idx++, sid_buf, &sid_len, nullptr, nullptr, nullptr,
                         nullptr) == ERROR_SUCCESS) {
        yuzu::profiles::RawProfileRecord rec;
        rec.sid = from_wide(sid_buf, static_cast<int>(sid_len));
        sid_len = kSidBufLen;

        RegKey sid_key;
        if (RegOpenKeyExW(profiles.get(), to_wide(rec.sid).c_str(), 0, KEY_READ, sid_key.put()) ==
            ERROR_SUCCESS) {
            wchar_t path_buf[512]{};
            DWORD path_size = sizeof(path_buf); // BYTES
            DWORD type = 0;
            if (RegQueryValueExW(sid_key.get(), L"ProfileImagePath", nullptr, &type,
                                 reinterpret_cast<LPBYTE>(path_buf), &path_size) ==
                    ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ)) {
                std::size_t nch = path_size / sizeof(wchar_t);
                while (nch > 0 && path_buf[nch - 1] == L'\0')
                    --nch;
                // ProfileImagePath may be REG_EXPAND_SZ -- expand once, here,
                // so every downstream consumer sees a literal path.
                const std::wstring expanded = expand_env_strings(std::wstring(path_buf, nch));
                rec.profile_image_path =
                    from_wide(expanded.c_str(), static_cast<int>(expanded.size()));
            }
            // An unreadable/absent ProfileImagePath leaves profile_image_path
            // empty on this record -- the record itself is still emitted.
        }
        out.push_back(std::move(rec));
    }
    if (truncated)
        *truncated = (out.size() >= kMaxProfiles);
    return out;
}

// Subkey names directly under HKEY_USERS -- live-loaded hive roots, plus any
// "<SID>_Classes" siblings. This is the input to
// yuzu::profiles::classify_hive_state.
inline std::vector<std::string> enumerate_hku_subkeys() {
    std::vector<std::string> out;
    constexpr DWORD kNameBufLen = 256;
    wchar_t name_buf[kNameBufLen]{};
    DWORD idx = 0;
    DWORD name_len = kNameBufLen;
    while (RegEnumKeyExW(HKEY_USERS, idx++, name_buf, &name_len, nullptr, nullptr, nullptr,
                         nullptr) == ERROR_SUCCESS) {
        out.push_back(from_wide(name_buf, static_cast<int>(name_len)));
        name_len = kNameBufLen;
    }
    return out;
}

// RAII scope that enables a token privilege the service account holds but
// which may start disabled -- RegLoadKeyW requires BOTH SeBackupPrivilege
// and SeRestorePrivilege enabled (granted by
// scripts/install-agent-user.ps1; a hardened install may strip them) -- and
// restores the token's PRIOR attributes for that privilege on scope exit.
// licensing_win.cpp's enable_privilege (the accepted precedent this ladder
// was ported from) leaves the privilege enabled for the rest of the
// process; this type closes that gap without touching that file. Checks
// GetLastError()==ERROR_SUCCESS after the enabling AdjustTokenPrivileges,
// which "succeeds" even when the privilege is absent from the token
// entirely (ERROR_NOT_ALL_ASSIGNED) -- a bare return-value check would
// misreport that case as success. Move-only via deleted copy ops; not
// move-enabled either since every call site constructs it in place.
class PrivilegeScope {
public:
    explicit PrivilegeScope(const wchar_t* name) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_))
            return;

        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
            CloseHandle(token_);
            token_ = nullptr;
            return;
        }

        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        const BOOL adjusted =
            AdjustTokenPrivileges(token_, FALSE, &tp, sizeof(previous_), &previous_, nullptr);
        ok_ = adjusted && GetLastError() == ERROR_SUCCESS;
        have_previous_ = adjusted;
    }

    PrivilegeScope(const PrivilegeScope&) = delete;
    PrivilegeScope& operator=(const PrivilegeScope&) = delete;

    ~PrivilegeScope() {
        // Restore whatever AdjustTokenPrivileges reported as the PRIOR
        // state, even when this scope failed to enable the privilege (a
        // partial/no-op adjustment still needs no undo, and previous_ is
        // zero-initialised in that case, making this a harmless no-op).
        if (token_ && have_previous_)
            AdjustTokenPrivileges(token_, FALSE, &previous_, 0, nullptr, nullptr);
        if (token_)
            CloseHandle(token_);
    }

    [[nodiscard]] bool ok() const { return ok_; }

private:
    HANDLE token_{};
    TOKEN_PRIVILEGES previous_{};
    bool have_previous_ = false;
    bool ok_ = false;
};

/// Outcome of with_user_hive's access ladder, rendered honestly by the
/// caller instead of collapsing every non-ok case to silence.
enum class HiveAccessStatus {
    ok,                // fn was called against a reachable root
    not_found,         // no live hive and no offline profile path to mount
    privilege_missing, // an offline mount was needed but SeBackup/SeRestore
                       // could not both be enabled
    mount_failed,      // an offline mount was attempted (privileges ok) and
                       // RegLoadKeyW (or the subsequent root open) failed
};

// The live-hive-first, offline-mount-fallback ladder (C-1): tries
// HKU\<sid> first; only if that is absent does it enable
// SeBackup/SeRestore and mount `<profile_path>\NTUSER.DAT` under a private
// "YUZU_HIVE_<sid>" name via ScopedUserHive. Calls fn(root_hkey) with
// whichever root it found, exactly once, iff a root was reachable.
// `unload_failed`, if non-null, is forwarded to the internal ScopedUserHive
// and set (never cleared) if the offline mount's RegUnLoadKeyW fails on the
// way out -- read it AFTER this call returns. The caller must surface a set
// flag rather than drop it: a failed unload leaves a system-wide mount that
// survives process death and locks the profile's NTUSER.DAT until it is
// unloaded or the host reboots (see win_reg_handle.hpp's ScopedUserHive
// doc comment for the common transient-holder case reboot isn't actually
// required for).
template <typename Fn>
HiveAccessStatus with_user_hive(const std::string& sid, const std::string& profile_path_utf8,
                                Fn&& fn, bool* unload_failed = nullptr) {
    const std::wstring wsid = to_wide(sid);

    RegKey live;
    if (RegOpenKeyExW(HKEY_USERS, wsid.c_str(), 0, KEY_READ, live.put()) == ERROR_SUCCESS) {
        fn(live.get());
        return HiveAccessStatus::ok;
    }

    if (profile_path_utf8.empty())
        return HiveAccessStatus::not_found;

    // R15: the offline-hive fallback rides SeBackupPrivilege/SeRestorePrivilege,
    // which the agent account already holds (docs/agent-privilege-model.md) --
    // this introduces no new privilege grant. Scoped to this function so both
    // privileges revert to their PRIOR token attributes once the offline
    // mount is no longer needed, rather than staying enabled for the rest of
    // the process.
    PrivilegeScope backup_priv(L"SeBackupPrivilege");
    PrivilegeScope restore_priv(L"SeRestorePrivilege");
    if (!backup_priv.ok() || !restore_priv.ok())
        return HiveAccessStatus::privilege_missing;

    const std::wstring ntuser = to_wide(profile_path_utf8) + L"\\NTUSER.DAT";
    const std::wstring mount = L"YUZU_HIVE_" + wsid;
    ScopedUserHive hive(mount, ntuser, unload_failed);

    bool called = false;
    hive.with_root([&](HKEY root) {
        fn(root);
        called = true;
    });
    return called ? HiveAccessStatus::ok : HiveAccessStatus::mount_failed;
}

/// Outcome of read_reg_value -- distinct from a plain bool so the caller can
/// report an honest reason instead of collapsing every failure into "not
/// found" (an oversized value and a genuinely absent one are different
/// facts and deserve different error text).
enum class ReadValueStatus {
    ok,        // out_value/out_type_name populated
    not_found, // the key or value does not exist
    oversized, // exists but exceeds kMaxRegValueBytes
    malformed, // exists with a declared numeric type but a size too small
              // for that type (e.g. a REG_DWORD value under 4 bytes)
};

// Reads a single string/DWORD/QWORD/binary value under `root`, formatting it
// the same way registry_plugin.cpp's existing do_get_value does (hex-encode
// for anything else). On ok, fills `out_value` and `out_type_name`. Bounded
// to kMaxRegValueBytes.
inline ReadValueStatus read_reg_value(HKEY root, const std::string& value_name,
                                      std::string& out_value, std::string& out_type_name) {
    const std::wstring wname = to_wide(value_name);
    DWORD type = 0, size = 0;
    if (RegQueryValueExW(root, wname.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
        return ReadValueStatus::not_found;

    const bool exceeds_cap = size > kMaxRegValueBytes;
    if (exceeds_cap)
        size = kMaxRegValueBytes;

    std::vector<BYTE> data(size);
    if (RegQueryValueExW(root, wname.c_str(), nullptr, &type, data.data(), &size) != ERROR_SUCCESS) {
        // A capped buffer that was too small for the real value surfaces
        // here as ERROR_MORE_DATA -- an honestly oversized value, not a
        // missing one. Any other failure at this point is a genuine miss
        // (e.g. the value was deleted between the two queries).
        return exceeds_cap ? ReadValueStatus::oversized : ReadValueStatus::not_found;
    }

    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        out_value = reg_sz_to_utf8(reinterpret_cast<const wchar_t*>(data.data()), size);
        out_type_name = (type == REG_SZ) ? "REG_SZ" : "REG_EXPAND_SZ";
        break;
    case REG_DWORD: {
        if (size < sizeof(DWORD))
            return ReadValueStatus::malformed;
        DWORD v = 0;
        std::memcpy(&v, data.data(), sizeof(v));
        out_value = std::to_string(v);
        out_type_name = "REG_DWORD";
        break;
    }
    case REG_QWORD: {
        if (size < sizeof(std::uint64_t))
            return ReadValueStatus::malformed;
        std::uint64_t v = 0;
        std::memcpy(&v, data.data(), sizeof(v));
        out_value = std::to_string(v);
        out_type_name = "REG_QWORD";
        break;
    }
    default:
        out_value.clear();
        for (DWORD i = 0; i < size; ++i) {
            constexpr char kHex[] = "0123456789abcdef";
            out_value += kHex[(data[i] >> 4) & 0xF];
            out_value += kHex[data[i] & 0xF];
        }
        out_type_name = (type == REG_BINARY) ? "REG_BINARY" : "REG_UNKNOWN";
        break;
    }
    return ReadValueStatus::ok;
}

} // namespace yuzu::win

#endif // _WIN32
