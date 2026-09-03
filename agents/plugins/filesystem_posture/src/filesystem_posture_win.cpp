/**
 * filesystem_posture_win.cpp — Windows leg entry points for the
 * filesystem_posture plugin (mounts/quotas/snapshots).
 *
 * COMPILE-VERIFIED ONLY (all three entry points below): this TU is checked
 * with `clang++ -fsyntax-only` on macOS with its body preprocessed away
 * (nothing here compiles outside `#if defined(_WIN32)`) and is expected to
 * build under MSVC in CI, but NO PART OF IT has been exercised against a
 * live Windows host in this change -- not the volume-enumeration walk, not
 * the IDiskQuotaControl COM path, not the FSCTL_SRV_ENUMERATE_SNAPSHOTS
 * buffer decode. The MSVC CI leg is the first real compiler this file sees;
 * a live Windows agent run is the first real runtime exercise.
 *
 * Two SDK surfaces are soft-guarded because their availability at build time
 * is not something this host can verify, and neither guard's failure is
 * allowed to silently look like success:
 *   - `<dskquota.h>` (quota state) via `__has_include`; a build lacking it
 *     reports every volume `unavailable` and degrades the result.
 *   - `FSCTL_SRV_ENUMERATE_SNAPSHOTS` (shadow-copy enumeration) via
 *     `#ifdef`; an SDK too old to define it reports the same way.
 *
 * Every OS call here is read-only: no write/format/delete right is ever
 * requested on a volume handle, quota control instance, or drive.
 */

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

#include <win_com.hpp>
#include <win_str.hpp>

#include "filesystem_posture_legs.hpp"

// initguid.h must precede dskquota.h in exactly this TU: it makes dskquota.h
// DEFINE (not merely declare) CLSID_DiskQuotaControl / IID_IDiskQuotaControl
// as local storage, so this TU needs no uuid.lib dependency.
#if __has_include(<dskquota.h>)
#define YUZU_FSPOSTURE_HAVE_DSKQUOTA 1
#include <initguid.h>
#include <dskquota.h>
#endif

#include <cstddef>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <cstring> // std::memcpy for the FSCTL framing header
#include <vector>

namespace yuzu::filesystem_posture {

namespace {

// RAII guard: set the thread error mode on construction, restore on scope
// exit. Local copy of disk_space_plugin.cpp:61's ThreadErrorModeGuard --
// that class is private to disk_space_plugin.cpp, not a shared header (peer
// M12); promoting it to agents/shared/ is a follow-up outside this PR.
// Suppresses the session-0 hard-error dialog around a volume query against a
// not-ready removable / BitLocker-locked volume, which would otherwise block
// a dispatch-pool worker. Thread-scoped -- never the process-wide
// SetErrorMode, which would race other workers in the bounded pool.
class ThreadErrorModeGuard {
public:
    explicit ThreadErrorModeGuard(DWORD mode) noexcept { ::SetThreadErrorMode(mode, &prev_); }
    ~ThreadErrorModeGuard() { ::SetThreadErrorMode(prev_, nullptr); }
    ThreadErrorModeGuard(const ThreadErrorModeGuard&) = delete;
    ThreadErrorModeGuard& operator=(const ThreadErrorModeGuard&) = delete;

private:
    DWORD prev_ = 0;
};

// RAII owner for a plain file/volume HANDLE (CloseHandle on scope exit).
// Local to this TU: agents/shared/win_sc_handle.hpp's ScHandle closes via
// CloseServiceHandle (a different API for a different handle kind), so it is
// not the right owner for a CreateFileW volume-root handle.
class ScopedFileHandle {
public:
    explicit ScopedFileHandle(HANDLE h) noexcept : h_(h) {}
    ~ScopedFileHandle() {
        if (valid())
            ::CloseHandle(h_);
    }
    ScopedFileHandle(const ScopedFileHandle&) = delete;
    ScopedFileHandle& operator=(const ScopedFileHandle&) = delete;

    [[nodiscard]] HANDLE get() const { return h_; }
    [[nodiscard]] bool valid() const { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

// RAII owner for a volume-search handle from FindFirstVolumeW (closes via
// FindVolumeClose, a different API from CloseHandle). Fix-round addition
// (peer review M-finding): a bare local HANDLE plus a FindVolumeClose() call
// reached only at normal loop exit leaks the search handle if anything in
// the loop body throws (std::format/allocation/ctx.write_output all can);
// tying the close to a destructor makes every exit path -- return, break,
// or an exception unwinding through this scope -- safe.
class ScopedVolumeFindHandle {
public:
    explicit ScopedVolumeFindHandle(HANDLE h) noexcept : h_(h) {}
    ~ScopedVolumeFindHandle() {
        if (valid())
            ::FindVolumeClose(h_);
    }
    ScopedVolumeFindHandle(const ScopedVolumeFindHandle&) = delete;
    ScopedVolumeFindHandle& operator=(const ScopedVolumeFindHandle&) = delete;

    [[nodiscard]] HANDLE get() const { return h_; }
    [[nodiscard]] bool valid() const { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

// Fixed vocabulary (peer M5): "ro" xor "rw", plus at most one of
// removable/remote/cdrom, derived only from enum/bitmask values -- never
// from parsed text.
std::string flags_for_volume(DWORD fs_flags, UINT drive_type) {
    std::string out = (fs_flags & FILE_READ_ONLY_VOLUME) ? "ro" : "rw";
    switch (drive_type) {
    case DRIVE_REMOVABLE:
        out += ",removable";
        break;
    case DRIVE_REMOTE:
        out += ",remote";
        break;
    case DRIVE_CDROM:
        out += ",cdrom";
        break;
    default:
        break;
    }
    return out;
}

// Enumerates local volume GUID paths (trailing-backslash form, e.g.
// "\\?\Volume{...}\\") via FindFirstVolumeW/FindNextVolumeW, always closing
// the find handle via FindVolumeClose before returning. `ok` is false only
// when the enumeration itself failed (FindFirstVolumeW, or FindNextVolumeW
// with an error other than the expected ERROR_NO_MORE_FILES end-of-list);
// `err` carries the Win32 error in that case.
std::vector<std::wstring> enumerate_volume_guid_paths(bool& ok, DWORD& err) {
    ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};
    std::vector<std::wstring> out;
    wchar_t volume_name[MAX_PATH] = {};
    const ScopedVolumeFindHandle find(::FindFirstVolumeW(volume_name, MAX_PATH));
    if (!find.valid()) {
        ok = false;
        err = ::GetLastError();
        return out;
    }
    ok = true;
    for (;;) {
        out.emplace_back(volume_name);
        if (!::FindNextVolumeW(find.get(), volume_name, MAX_PATH)) {
            const DWORD last_err = ::GetLastError();
            if (last_err != ERROR_NO_MORE_FILES) {
                ok = false;
                err = last_err;
            }
            break;
        }
    }
    return out;
}

// The volume's first drive-letter-style mount path (e.g. "C:\\"), or the
// volume GUID path itself when GetVolumePathNamesForVolumeNameW reports no
// mount point -- the same "always something to key the row on" choice
// emit_mounts makes per path.
std::wstring primary_mount_point(const std::wstring& volume_guid) {
    DWORD needed = 0;
    ::GetVolumePathNamesForVolumeNameW(volume_guid.c_str(), nullptr, 0, &needed);
    if (needed > 0) {
        std::vector<wchar_t> buf(needed, L'\0');
        if (::GetVolumePathNamesForVolumeNameW(volume_guid.c_str(), buf.data(), needed, &needed) &&
            !buf.empty() && buf[0] != L'\0') {
            return std::wstring(buf.data());
        }
    }
    return volume_guid;
}

// ── mounts ───────────────────────────────────────────────────────────────

void emit_one_mount_row(yuzu::CommandContext& ctx, const wchar_t* mount_point_w,
                        const std::string& device, const std::string& fstype,
                        const std::string& flags) {
    const std::string mount_point = yuzu::win::from_wide(mount_point_w);

    std::optional<unsigned long long> total;
    std::optional<unsigned long long> free_bytes;
    std::optional<unsigned long long> available;

    ULARGE_INTEGER avail_to_caller{};
    ULARGE_INTEGER total_bytes{};
    ULARGE_INTEGER total_free{};
    if (::GetDiskFreeSpaceExW(mount_point_w, &avail_to_caller, &total_bytes, &total_free)) {
        total = total_bytes.QuadPart;
        free_bytes = total_free.QuadPart;
        available = avail_to_caller.QuadPart;
    } else {
        mark_result_partial(ctx, "windows:volume_enum",
                            std::format("{} GetDiskFreeSpaceExW failed: {}", mount_point,
                                        ::GetLastError()));
    }
    // No per-mount option string exists on this leg (peer H1 fallback
    // prose); the options column is always "-".
    write_mount_row(ctx, mount_point, device, fstype, "-", total, free_bytes, available, flags);
}

// One volume: resolve its filesystem name/flags once, then emit one row per
// GetVolumePathNamesForVolumeNameW path (or one row keyed by the volume GUID
// path itself when it has no mount point). Any single API failure for this
// volume degrades that row's columns to "-"/nullopt and reports via
// mark_result_partial rather than dropping the row or aborting the walk.
void emit_mount_rows_for_volume(yuzu::CommandContext& ctx, const wchar_t* volume_guid) {
    const std::string device = yuzu::win::from_wide(volume_guid);

    wchar_t vol_label[MAX_PATH + 1] = {};
    wchar_t fs_name[MAX_PATH + 1] = {};
    DWORD serial = 0;
    DWORD max_component = 0;
    DWORD fs_flags = 0;
    const BOOL info_ok = ::GetVolumeInformationW(volume_guid, vol_label, MAX_PATH, &serial,
                                                 &max_component, &fs_flags, fs_name, MAX_PATH);
    std::string fstype = "-";
    std::string flags = "-";
    if (info_ok) {
        fstype = yuzu::win::from_wide(fs_name);
        if (fstype.empty())
            fstype = "-";
        // DRIVE_UNKNOWN means GetDriveTypeW could not classify the volume
        // (e.g. a not-ready removable) -- that is itself a failure, not a
        // fifth drive-type category, so it must degrade the flags column
        // rather than silently pass through as an unqualified "ro"/"rw".
        const UINT drive_type = ::GetDriveTypeW(volume_guid);
        if (drive_type == DRIVE_UNKNOWN) {
            mark_result_partial(ctx, "windows:volume_enum",
                                std::format("{} GetDriveTypeW returned DRIVE_UNKNOWN", device));
        } else {
            flags = flags_for_volume(fs_flags, drive_type);
        }
    } else {
        mark_result_partial(ctx, "windows:volume_enum",
                            std::format("{} GetVolumeInformationW failed: {}", device,
                                        ::GetLastError()));
    }

    // The sizing call is expected to fail with ERROR_MORE_DATA when the
    // volume has mount points to report; needed==0 with any OTHER error is
    // a genuine enumeration failure that must not masquerade as the
    // legitimate "this volume has zero mount points" case (peer H6-style
    // failure/emptiness distinction, applied here too).
    DWORD path_chars = 0;
    const BOOL sized_ok = ::GetVolumePathNamesForVolumeNameW(volume_guid, nullptr, 0, &path_chars);
    const DWORD sizing_err = sized_ok ? ERROR_SUCCESS : ::GetLastError();
    std::vector<wchar_t> path_buf;
    bool have_paths = false;
    bool paths_query_failed = false;
    DWORD paths_query_err = sizing_err;
    if (path_chars > 0) {
        path_buf.assign(path_chars, L'\0');
        if (::GetVolumePathNamesForVolumeNameW(volume_guid, path_buf.data(), path_chars,
                                               &path_chars) &&
            !path_buf.empty() && path_buf[0] != L'\0') {
            have_paths = true;
        } else {
            paths_query_failed = true;
            paths_query_err = ::GetLastError();
        }
    } else if (!sized_ok && sizing_err != ERROR_MORE_DATA) {
        paths_query_failed = true;
    }
    if (paths_query_failed) {
        mark_result_partial(ctx, "windows:volume_enum",
                            std::format("{} GetVolumePathNamesForVolumeNameW failed: {}", device,
                                        paths_query_err));
    }

    if (have_paths) {
        const wchar_t* p = path_buf.data();
        while (*p) {
            const std::wstring mp_w(p);
            emit_one_mount_row(ctx, mp_w.c_str(), device, fstype, flags);
            p += mp_w.size() + 1;
        }
    } else {
        emit_one_mount_row(ctx, volume_guid, device, fstype, flags);
    }
}

// ── quotas ───────────────────────────────────────────────────────────────

#if defined(YUZU_FSPOSTURE_HAVE_DSKQUOTA)

void emit_quota_rows_dskquota(yuzu::CommandContext& ctx, const std::vector<std::wstring>& volumes) {
    yuzu::shared::win::ComInit com;
    const bool com_ok = com.ok();
    bool any_ntfs = false;
    bool any_success = false;

    for (const auto& vol : volumes) {
        const std::wstring mount_w = primary_mount_point(vol);
        const std::string mp = yuzu::win::from_wide(mount_w.c_str());

        wchar_t fs_name[MAX_PATH + 1] = {};
        const BOOL info_ok = ::GetVolumeInformationW(vol.c_str(), nullptr, 0, nullptr, nullptr,
                                                     nullptr, fs_name, MAX_PATH);
        if (!info_ok) {
            write_quota_row(ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            "volume filesystem type unavailable");
            continue;
        }
        if (yuzu::win::from_wide(fs_name) != "NTFS") {
            write_quota_row(ctx, mp, QuotaState::UnsupportedFs, std::nullopt, std::nullopt, "-");
            continue;
        }
        any_ntfs = true;

        // IDiskQuotaControl::Initialize is meant to be handed a drive-letter
        // root path ("per LETTERED NTFS volume" in the spec): a volume with
        // no drive letter (mounted only at a folder, or not mounted at all)
        // has no such root, and quietly substituting the raw volume GUID
        // path there would be an unrequested scope widening, not a graceful
        // fallback -- report it and move on instead.
        const bool lettered = mount_w.size() == 3 && mount_w[1] == L':' && mount_w[2] == L'\\' &&
                              ((mount_w[0] >= L'A' && mount_w[0] <= L'Z') ||
                               (mount_w[0] >= L'a' && mount_w[0] <= L'z'));
        if (!lettered) {
            write_quota_row(ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            "volume has no drive letter");
            continue;
        }

        if (!com_ok) {
            write_quota_row(ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            "COM apartment initialization failed");
            continue;
        }

        yuzu::shared::win::ComPtr<IDiskQuotaControl> quota_ctl;
        HRESULT hr = ::CoCreateInstance(CLSID_DiskQuotaControl, nullptr, CLSCTX_INPROC_SERVER,
                                        IID_IDiskQuotaControl,
                                        reinterpret_cast<void**>(quota_ctl.put()));
        if (SUCCEEDED(hr)) {
            // Read-only (peer H4): TRUE here requests read/write access to
            // the quota control and fails E_ACCESSDENIED for a
            // non-Administrator agent identity on every volume. FALSE is
            // sufficient for GetQuotaState/GetDefaultQuotaLimit/
            // GetDefaultQuotaThreshold, and matches this plugin's ReadOnly
            // capability classification.
            hr = quota_ctl->Initialize(mount_w.c_str(), FALSE);
        }

        const auto write_hresult_failure = [&](HRESULT failed_hr) {
            if (failed_hr == E_ACCESSDENIED) {
                write_quota_row(ctx, mp, QuotaState::PermissionDenied, std::nullopt, std::nullopt,
                                "-");
            } else {
                write_quota_row(
                    ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                    std::format("hr=0x{:08X}", static_cast<unsigned long>(failed_hr)));
            }
        };

        if (FAILED(hr)) {
            write_hresult_failure(hr);
            continue;
        }

        DWORD state_flags = 0;
        const HRESULT state_hr = quota_ctl->GetQuotaState(&state_flags);
        if (FAILED(state_hr)) {
            write_hresult_failure(state_hr);
            continue;
        }

        // GetQuotaState's DWORD carries DISKQUOTA_FILESTATE_* bits alongside
        // the state -- mask with DISKQUOTA_STATE_MASK (0x3) before comparing
        // (a raw == would misclassify a rebuilding/incomplete volume).
        const DWORD state = state_flags & DISKQUOTA_STATE_MASK;
        if (state == DISKQUOTA_STATE_DISABLED) {
            write_quota_row(ctx, mp, QuotaState::NotEnabled, std::nullopt, std::nullopt, "-");
            any_success = true;
            continue;
        }
        if (state != DISKQUOTA_STATE_TRACK && state != DISKQUOTA_STATE_ENFORCE) {
            // The mask covers 2 bits (0-3); DISABLED/TRACK/ENFORCE are the
            // only documented values. The remaining (reserved) value is not
            // a healthy default to fold silently into "configured".
            write_quota_row(ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            std::format("unrecognized quota state: {}", state));
            continue;
        }

        // TRACK or ENFORCE: read the default limit/threshold. There is no
        // NOQUOTA macro in dskquota.h -- the no-limit sentinel is -1
        // (0xFFFFFFFFFFFFFFFF as LONGLONG), which renders as nullopt/"-".
        // Both reads' HRESULTs are checked: a failure here (e.g.
        // E_ACCESSDENIED mid-session) must degrade this row rather than
        // fall through to an unqualified "configured" built on values that
        // were never actually written by a failed out-param call.
        LONGLONG limit = -1;
        const HRESULT limit_hr = quota_ctl->GetDefaultQuotaLimit(&limit);
        if (FAILED(limit_hr)) {
            write_hresult_failure(limit_hr);
            continue;
        }
        LONGLONG threshold = -1;
        const HRESULT threshold_hr = quota_ctl->GetDefaultQuotaThreshold(&threshold);
        if (FAILED(threshold_hr)) {
            write_hresult_failure(threshold_hr);
            continue;
        }
        const std::optional<unsigned long long> limit_opt =
            limit == -1 ? std::nullopt
                       : std::optional<unsigned long long>(static_cast<unsigned long long>(limit));
        const std::optional<unsigned long long> threshold_opt =
            threshold == -1
                ? std::nullopt
                : std::optional<unsigned long long>(static_cast<unsigned long long>(threshold));

        write_quota_row(ctx, mp, QuotaState::Configured, limit_opt, threshold_opt, "-");
        any_success = true;
    }

    if (any_ntfs && !any_success) {
        mark_result_partial(ctx, "windows:dskquota", "quota query failed on every NTFS volume");
    }
}

#endif // YUZU_FSPOSTURE_HAVE_DSKQUOTA

// ── snapshots ────────────────────────────────────────────────────────────

#ifdef FSCTL_SRV_ENUMERATE_SNAPSHOTS

void emit_snapshot_rows_fsctl(yuzu::CommandContext& ctx, const std::vector<std::wstring>& volumes) {
    bool any_failure = false;
    DWORD first_failure_err = 0;
    bool any_tokens = false;
    bool any_truncated = false;

    for (const auto& vol : volumes) {
        const std::string mp = yuzu::win::from_wide(primary_mount_point(vol).c_str());

        // CreateFileW wants the volume root WITHOUT the trailing backslash
        // that GetVolumeInformationW/GetDriveTypeW/GetDiskFreeSpaceExW need.
        std::wstring root = vol;
        if (!root.empty() && root.back() == L'\\')
            root.pop_back();

        // Read-only rights ONLY. FILE_READ_DATA is required: the FSCTL's
        // CTL_CODE carries FILE_READ_DATA access, and opening with
        // FILE_READ_ATTRIBUTES|SYNCHRONIZE alone fails ACCESS_DENIED on
        // every volume -- a self-inflicted rights bug that this function's
        // own failure/empty distinction would otherwise misreport as a
        // genuine FSCTL failure.
        const HANDLE raw_handle =
            ::CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES | FILE_READ_DATA | SYNCHRONIZE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        const ScopedFileHandle handle(raw_handle);
        if (!handle.valid()) {
            any_failure = true;
            if (first_failure_err == 0)
                first_failure_err = ::GetLastError();
            continue;
        }

        std::vector<std::byte> buf(65536);
        DWORD returned = 0;
        const BOOL ok =
            ::DeviceIoControl(handle.get(), FSCTL_SRV_ENUMERATE_SNAPSHOTS, nullptr, 0, buf.data(),
                              static_cast<DWORD>(buf.size()), &returned, nullptr);
        if (!ok) {
            any_failure = true;
            if (first_failure_err == 0)
                first_failure_err = ::GetLastError();
            continue;
        }

        // Fixed 3-ULONG header: NumberOfSnapShots, NumberOfSnapShotsReturned,
        // SnapShotArraySize -- the trailing bytes are the UTF-16LE
        // double-NUL multistring.
        constexpr std::size_t kHeaderBytes = 3 * sizeof(ULONG);
        if (returned < kHeaderBytes) {
            any_failure = true;
            if (first_failure_err == 0)
                first_failure_err = ERROR_INVALID_DATA;
            continue;
        }

        // CDX-P2-06: the three framing ULONGs were documented but never read,
        // so the walker parsed everything after the header regardless of what
        // the driver said the array actually contains. Read them and let them
        // bound the walk. All three are native-endian in a locally-filled
        // DeviceIoControl buffer, so memcpy rather than a byte-order helper.
        ULONG number_of_snapshots = 0;
        ULONG number_returned = 0;
        ULONG array_size_bytes = 0;
        std::memcpy(&number_of_snapshots, buf.data() + 0 * sizeof(ULONG), sizeof(ULONG));
        std::memcpy(&number_returned, buf.data() + 1 * sizeof(ULONG), sizeof(ULONG));
        std::memcpy(&array_size_bytes, buf.data() + 2 * sizeof(ULONG), sizeof(ULONG));

        const std::size_t available = returned - kHeaderBytes;
        // A declared array larger than what was actually returned means the
        // reply is short: the payload cannot be trusted to be complete.
        if (static_cast<std::size_t>(array_size_bytes) > available) {
            any_failure = true;
            if (first_failure_err == 0)
                first_failure_err = ERROR_INVALID_DATA;
            continue;
        }
        // Trust the DECLARED length over the returned byte count -- trailing
        // bytes beyond SnapShotArraySize are not part of the multistring.
        const std::size_t payload_bytes =
            array_size_bytes > 0 ? static_cast<std::size_t>(array_size_bytes) : available;

        const std::span<const std::byte> payload(buf.data() + kHeaderBytes, payload_bytes);
        // NumberOfSnapShotsReturned bounds how many names the array may hold.
        const SnapshotNames names =
            parse_gmt_multistring(payload, number_returned > 0
                                              ? static_cast<std::size_t>(number_returned)
                                              : 1024);
        if (names.malformed) {
            any_failure = true;
            if (first_failure_err == 0)
                first_failure_err = ERROR_INVALID_DATA;
            continue;
        }
        if (names.truncated)
            any_truncated = true;
        for (const auto& name : names.names) {
            write_snapshot_row(ctx, mp, name, "vss", "-");
            any_tokens = true;
        }
    }

    // Failure must be distinguishable from emptiness (peer H6): an
    // ERROR_INVALID_FUNCTION on every volume must never masquerade as "no
    // backups". Only report the clean, genuinely-empty sentinel when every
    // volume's DeviceIoControl actually succeeded.
    if (any_failure) {
        const std::string detail =
            std::format("FSCTL_SRV_ENUMERATE_SNAPSHOTS failed: {}", first_failure_err);
        write_snapshot_row(ctx, "-", "-", "none", detail);
        mark_result_partial(ctx, "windows:fsctl_snapshots", detail);
    } else if (!any_tokens) {
        write_snapshot_row(ctx, "-", "-", "none", "no shadow copies exposed on any volume");
    } else if (any_truncated) {
        // Tokens were found and emitted, but at least one volume's list hit
        // parse_gmt_multistring's 1024-entry cap -- the visible rows are
        // real, but the set is known incomplete, so this must not read as a
        // clean, complete result.
        mark_result_partial(ctx, "windows:fsctl_snapshots",
                            "snapshot list truncated at 1024 entries on at least one volume");
    }
}

#endif // FSCTL_SRV_ENUMERATE_SNAPSHOTS

} // namespace

// ── entry points ─────────────────────────────────────────────────────────
//
// Each is a read; each returns 0 unconditionally (ADR-style: a read never
// fails the call, degradation is reported via mark_result_partial).

int emit_mounts(yuzu::CommandContext& ctx) {
    ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};
    wchar_t volume_name[MAX_PATH] = {};
    const ScopedVolumeFindHandle find(::FindFirstVolumeW(volume_name, MAX_PATH));
    if (!find.valid()) {
        mark_result_partial(ctx, "windows:volume_enum",
                            std::format("FindFirstVolumeW failed: {}", ::GetLastError()));
    } else {
        for (;;) {
            emit_mount_rows_for_volume(ctx, volume_name);
            if (!::FindNextVolumeW(find.get(), volume_name, MAX_PATH)) {
                const DWORD err = ::GetLastError();
                if (err != ERROR_NO_MORE_FILES) {
                    mark_result_partial(ctx, "windows:volume_enum",
                                        std::format("FindNextVolumeW failed: {}", err));
                }
                break;
            }
        }
    }
    return 0;
}

int emit_quotas(yuzu::CommandContext& ctx) {
    bool enum_ok = false;
    DWORD enum_err = 0;
    // A mid-walk FindNextVolumeW failure still leaves `volumes` holding
    // every entry collected before the failure -- those are real volumes
    // that were genuinely enumerated, so they are queried below rather than
    // discarded; the enumeration failure itself is reported separately via
    // mark_result_partial so it is never silently dropped either.
    const std::vector<std::wstring> volumes = enumerate_volume_guid_paths(enum_ok, enum_err);

    if (!enum_ok) {
        mark_result_partial(ctx, "windows:dskquota",
                            std::format("volume enumeration failed: {}", enum_err));
    }
    if (!volumes.empty()) {
#if defined(YUZU_FSPOSTURE_HAVE_DSKQUOTA)
        emit_quota_rows_dskquota(ctx, volumes);
#else
        for (const auto& vol : volumes) {
            const std::string mp = yuzu::win::from_wide(primary_mount_point(vol).c_str());
            write_quota_row(ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            "built without dskquota.h");
        }
        mark_result_partial(ctx, "windows:dskquota", "SDK header dskquota.h not present at build time");
#endif
    }
    return 0;
}

int emit_snapshots(yuzu::CommandContext& ctx) {
    bool enum_ok = false;
    DWORD enum_err = 0;
    // Same partial-enumeration handling as emit_quotas: volumes collected
    // before a mid-walk FindNextVolumeW failure are still queried below,
    // never discarded outright.
    const std::vector<std::wstring> volumes = enumerate_volume_guid_paths(enum_ok, enum_err);

    if (!enum_ok) {
        const std::string detail = std::format("volume enumeration failed: {}", enum_err);
        // Only when volumes is empty do we have nothing left to try the
        // FSCTL against, so only then does the top-level "none" sentinel
        // need to carry this failure -- otherwise emit_snapshot_rows_fsctl
        // below reports on the volumes that WERE collected.
        if (volumes.empty())
            write_snapshot_row(ctx, "-", "-", "none", detail);
        mark_result_partial(ctx, "windows:fsctl_snapshots", detail);
    }
    if (!volumes.empty()) {
#ifdef FSCTL_SRV_ENUMERATE_SNAPSHOTS
        emit_snapshot_rows_fsctl(ctx, volumes);
#else
        write_snapshot_row(ctx, "-", "-", "none", "built without FSCTL_SRV_ENUMERATE_SNAPSHOTS");
        mark_result_partial(ctx, "windows:fsctl_snapshots", "built without FSCTL_SRV_ENUMERATE_SNAPSHOTS");
#endif
    }
    return 0;
}

} // namespace yuzu::filesystem_posture

#endif // defined(_WIN32)
