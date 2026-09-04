/**
 * disk_actions_win.cpp — Windows leg entry points.
 *
 * MECHANISMS, every one bound by spike against real hardware on 2026-09-03
 * (the-rig, live Samsung SSD 970 EVO Plus over NVMe) before a line of this was
 * written. The full record is at ~/.claude/roadmaps/wave6-smart-spike.md.
 *
 *   smart    IOCTL_STORAGE_QUERY_PROPERTY with StorageDeviceProperty (identity,
 *            bus type), StorageDeviceSeekPenaltyProperty (SSD vs HDD) and
 *            StorageDeviceProtocolSpecificProperty + ProtocolTypeNvme +
 *            NVMeDataTypeLogPage page 0x02 (the SMART/Health log).
 *   volumes  FindFirstVolumeW/FindNextVolumeW +
 *            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS (which physical drives back
 *            this volume) + GetVolumePathNamesForVolumeNameW (which mount
 *            points it serves).
 *
 * TWO SPIKE NEGATIVES, both load-bearing, both the kind of mistake that ships
 * a leg which silently never works:
 *
 *   1. THE DEVICE HANDLE IS OPENED WITH ZERO ACCESS RIGHTS, deliberately, and
 *      this is not a typo for GENERIC_READ. Measured: as NT AUTHORITY\LOCAL
 *      SERVICE, CreateFileW with GENERIC_READ fails ERROR_ACCESS_DENIED, while
 *      a 0-access handle succeeds and serves BOTH IOCTLs (they are
 *      FILE_ANY_ACCESS controls). That single detail is why this leg keeps
 *      working when #1442 moves the agent off LocalSystem — unlike the VSS
 *      snapshots leg in filesystem_posture, which genuinely requires admin.
 *      Do not "fix" this to GENERIC_READ.
 *
 *   2. IOCTL_STORAGE_PREDICT_FAILURE — the obvious "documented health bit" —
 *      FAILS with ERROR_INVALID_FUNCTION (1) on NVMe. It is the ATA-era API.
 *      This file does not use it, and a future edit that reaches for it should
 *      re-measure first rather than assume the docs describe modern drives.
 *
 * Every OS call here is read-only: no write, format or delete right is ever
 * requested on a drive or volume handle.
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
// nvme.h supplies STORAGE_PROTOCOL_SPECIFIC_DATA / ProtocolTypeNvme /
// NVMeDataTypeLogPage. Soft-guarded: an SDK without it still builds and
// reports identity, losing only the health figures.
#if __has_include(<nvme.h>)
#define YUZU_DISKACTIONS_HAVE_NVME 1
#include <nvme.h>
#endif

#include <win_str.hpp>

#include "disk_actions_legs.hpp"

#include <array>
#include <cstddef>
#include <cstring>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::disk_actions {

namespace {

/// RAII guard: set the thread error mode on construction, restore on scope
/// exit. Local copy of the same guard in disk_space_plugin.cpp and
/// filesystem_posture_win.cpp — promoting it into agents/shared/ is a
/// follow-up outside this change, noted so the third copy is a recorded
/// decision rather than an oversight.
///
/// It suppresses the session-0 hard-error dialog around a query against a
/// not-ready removable or BitLocker-locked volume, which would otherwise block
/// a bounded dispatch-pool worker. Thread-scoped, never the process-wide
/// SetErrorMode, which would race other workers in the same pool.
class ThreadErrorModeGuard {
public:
    explicit ThreadErrorModeGuard(DWORD mode) noexcept { ::SetThreadErrorMode(mode, &prev_); }
    ~ThreadErrorModeGuard() { ::SetThreadErrorMode(prev_, nullptr); }
    ThreadErrorModeGuard(const ThreadErrorModeGuard&) = delete;
    ThreadErrorModeGuard& operator=(const ThreadErrorModeGuard&) = delete;

private:
    DWORD prev_ = 0;
};

/// RAII owner for a device/volume HANDLE.
class ScopedFileHandle {
public:
    explicit ScopedFileHandle(HANDLE h) noexcept : h_(h) {}
    ~ScopedFileHandle() {
        if (valid()) ::CloseHandle(h_);
    }
    ScopedFileHandle(const ScopedFileHandle&) = delete;
    ScopedFileHandle& operator=(const ScopedFileHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    [[nodiscard]] bool valid() const noexcept {
        return h_ != nullptr && h_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

/// RAII owner for a FindFirstVolumeW search handle (FindVolumeClose, a
/// different API from CloseHandle).
class ScopedVolumeFindHandle {
public:
    explicit ScopedVolumeFindHandle(HANDLE h) noexcept : h_(h) {}
    ~ScopedVolumeFindHandle() {
        if (valid()) ::FindVolumeClose(h_);
    }
    ScopedVolumeFindHandle(const ScopedVolumeFindHandle&) = delete;
    ScopedVolumeFindHandle& operator=(const ScopedVolumeFindHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    [[nodiscard]] bool valid() const noexcept {
        return h_ != nullptr && h_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

constexpr int kMaxPhysicalDrives = 64; // bounds the probe walk; see emit_smart

/// Open \\.\PhysicalDriveN with ZERO access rights. See negative (1) in the
/// file banner: this is what an unprivileged service account may do, and it is
/// sufficient for every IOCTL this file issues.
ScopedFileHandle open_physical_drive(int index) {
    const std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(index);
    return ScopedFileHandle{::CreateFileW(path.c_str(), 0,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                          OPEN_EXISTING, 0, nullptr)};
}

Bus bus_from_storage_type(STORAGE_BUS_TYPE t) {
    switch (t) {
    case BusTypeNvme:  return Bus::Nvme;
    case BusTypeSata:
    case BusTypeAta:   return Bus::Sata;
    case BusTypeUsb:   return Bus::Usb;
    case BusTypeSas:   return Bus::Sas;
    case BusTypeVirtual:
    case BusTypeFileBackedVirtual: return Bus::Virtual;
    default: return Bus::Unknown;
    }
}

/// A counted, offset-based field from STORAGE_DEVICE_DESCRIPTOR. The offsets
/// are device-supplied, so every one is bounds-checked against the returned
/// byte count before it is dereferenced -- this is untrusted data shaped by
/// firmware, not by us.
std::string descriptor_field(const BYTE* buf, DWORD returned, DWORD offset) {
    if (offset == 0 || offset >= returned) return {};
    const char* p = reinterpret_cast<const char*>(buf) + offset;
    const std::size_t max = static_cast<std::size_t>(returned - offset);
    const std::size_t len = ::strnlen(p, max); // never runs past the reply
    std::string out(p, len);
    while (!out.empty() && (out.back() == ' ' || out.back() == '\t')) out.pop_back();
    return out;
}

struct DriveIdentity {
    std::string model;
    Bus bus{Bus::Unknown};
    Media media{Media::Unknown};
};

std::optional<DriveIdentity> query_identity(HANDLE h) {
    STORAGE_PROPERTY_QUERY q{};
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;
    std::array<BYTE, 1024> buf{};
    DWORD returned = 0;
    if (!::DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, buf.data(),
                           static_cast<DWORD>(buf.size()), &returned, nullptr))
        return std::nullopt;
    if (returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return std::nullopt;

    const auto* d = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buf.data());
    DriveIdentity id;
    id.bus = bus_from_storage_type(d->BusType);
    std::string product = descriptor_field(buf.data(), returned, d->ProductIdOffset);
    std::string vendor = descriptor_field(buf.data(), returned, d->VendorIdOffset);
    // NVMe puts the whole name in ProductId and leaves VendorId empty; SATA
    // often splits it. Join only when both are present, so a model never gains
    // a stray leading space.
    id.model = vendor.empty() ? product : (product.empty() ? vendor : vendor + " " + product);

    // Seek penalty is a separate query and its absence is not a failure -- a
    // device that will not answer is `unknown`, never guessed as either.
    STORAGE_PROPERTY_QUERY sq{};
    sq.PropertyId = StorageDeviceSeekPenaltyProperty;
    sq.QueryType = PropertyStandardQuery;
    DEVICE_SEEK_PENALTY_DESCRIPTOR sp{};
    DWORD sr = 0;
    if (::DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &sq, sizeof sq, &sp, sizeof sp, &sr,
                          nullptr) &&
        sr >= sizeof sp)
        id.media = sp.IncursSeekPenalty ? Media::Hdd : Media::Ssd;
    return id;
}

struct NvmeHealth {
    std::uint8_t critical_warning{0};
    std::uint8_t available_spare{0};
    std::uint8_t percentage_used{0};
};

#if defined(YUZU_DISKACTIONS_HAVE_NVME)
/// NVMe SMART / Health Information log page 0x02. Byte offsets are from the
/// NVMe specification: [0] critical warning, [3] available spare %,
/// [5] percentage used.
std::optional<NvmeHealth> query_nvme_health(HANDLE h) {
    struct Request {
        STORAGE_PROPERTY_QUERY query;
        STORAGE_PROTOCOL_SPECIFIC_DATA protocol;
        BYTE data[512];
    } req{};
    req.query.PropertyId = StorageDeviceProtocolSpecificProperty;
    req.query.QueryType = PropertyStandardQuery;

    auto* psd = reinterpret_cast<STORAGE_PROTOCOL_SPECIFIC_DATA*>(req.query.AdditionalParameters);
    psd->ProtocolType = ProtocolTypeNvme;
    psd->DataType = NVMeDataTypeLogPage;
    psd->ProtocolDataRequestValue = 2; // SMART / Health Information
    psd->ProtocolDataRequestSubValue = 0;
    psd->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    psd->ProtocolDataLength = sizeof(req.data);

    std::array<BYTE, sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR) + 512> out{};
    DWORD returned = 0;
    if (!::DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &req, sizeof req, out.data(),
                           static_cast<DWORD>(out.size()), &returned, nullptr))
        return std::nullopt;
    if (returned < sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR)) return std::nullopt;

    const auto* pd = reinterpret_cast<const STORAGE_PROTOCOL_DATA_DESCRIPTOR*>(out.data());
    // Both offset and length are device-supplied. Bound the whole span against
    // what was actually returned before touching a byte of it.
    const std::size_t base = offsetof(STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolSpecificData) +
                             pd->ProtocolSpecificData.ProtocolDataOffset;
    const std::size_t len = pd->ProtocolSpecificData.ProtocolDataLength;
    if (len < 6 || base > returned || base + len > returned) return std::nullopt;

    const BYTE* lp = out.data() + base;
    return NvmeHealth{lp[0], lp[3], lp[5]};
}
#endif // YUZU_DISKACTIONS_HAVE_NVME

/// Health from the NVMe critical-warning bitmask. Bit 0 is "available spare
/// below threshold" and bit 2 is "reliability degraded" -- the two an operator
/// must act on. Any other set bit still degrades to `warning` rather than being
/// ignored, because an unrecognised warning is not the same as no warning.
Health health_from_nvme(const NvmeHealth& h) {
    constexpr std::uint8_t kSpareBelowThreshold = 0x01;
    constexpr std::uint8_t kReliabilityDegraded = 0x04;
    if (h.critical_warning & (kSpareBelowThreshold | kReliabilityDegraded)) return Health::Failing;
    if (h.critical_warning != 0) return Health::Warning;
    return Health::Ok;
}

} // namespace

int emit_smart(yuzu::CommandContext& ctx) {
    ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};

    bool any_row = false;
    bool any_denied = false;
    bool any_open_failure = false;
    DWORD first_open_err = 0;

    // Windows exposes no enumeration of PhysicalDriveN, so probe a bounded
    // range. ERROR_FILE_NOT_FOUND simply means that index does not exist and is
    // the normal terminator; ACCESS_DENIED is a different fact and is reported.
    for (int i = 0; i < kMaxPhysicalDrives; ++i) {
        auto h = open_physical_drive(i);
        if (!h.valid()) {
            const DWORD err = ::GetLastError();
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) continue;
            if (err == ERROR_ACCESS_DENIED) {
                any_denied = true;
            } else {
                any_open_failure = true;
                if (first_open_err == 0) first_open_err = err;
            }
            continue;
        }

        const std::string device = "PhysicalDrive" + std::to_string(i);
        const auto id = query_identity(h.get());
        if (!id) {
            write_smart_row(ctx, device, "-", Bus::Unknown, Media::Unknown, Health::Unknown,
                            std::nullopt, std::nullopt,
                            std::format("StorageDeviceProperty query failed: {}", ::GetLastError()));
            any_row = true;
            continue;
        }

        Health health = Health::Unknown;
        std::optional<std::uint8_t> pct_used;
        std::optional<std::uint8_t> spare;
        std::string detail = "-";

#if defined(YUZU_DISKACTIONS_HAVE_NVME)
        if (id->bus == Bus::Nvme) {
            if (const auto nh = query_nvme_health(h.get())) {
                health = health_from_nvme(*nh);
                pct_used = nh->percentage_used;
                spare = nh->available_spare;
            } else {
                detail = "NVMe SMART log page 0x02 was not returned by this device";
            }
        } else {
            // Deliberate and declared: wear figures come from the NVMe health
            // log, so a SATA or USB drive reports identity and media type with
            // health `unknown` rather than a guess. IOCTL_STORAGE_PREDICT_FAILURE
            // is NOT a substitute -- see negative (2) in the file banner.
            detail = "wear and spare figures are read from the NVMe health log; this device is "
                     "not NVMe, so its health is not reported";
        }
#else
        detail = "built without the NVMe SDK header; health is not read";
#endif

        write_smart_row(ctx, device, id->model.empty() ? "-" : id->model, id->bus, id->media,
                        health, pct_used, spare, detail);
        any_row = true;
    }

    if (!any_row)
        write_smart_row(ctx, "-", "-", Bus::Unknown, Media::Unknown, Health::Unknown, std::nullopt,
                        std::nullopt, "no physical drives could be opened");

    // Reported after the walk, least-material first, so the most actionable
    // cause is the one that survives set_result_status's last-writer-wins.
    if (any_open_failure)
        mark_result_partial(ctx, "windows:physicaldrive",
                            std::format("at least one drive could not be opened: {}",
                                        first_open_err));
    if (any_denied)
        mark_result_denied(ctx, "windows:physicaldrive",
                           "at least one physical drive refused a zero-access open; this agent "
                           "account cannot enumerate it");
    return 0;
}

int emit_volumes(yuzu::CommandContext& ctx) {
    ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};

    wchar_t volume[MAX_PATH] = {};
    const ScopedVolumeFindHandle find{::FindFirstVolumeW(volume, MAX_PATH)};
    if (!find.valid()) {
        write_volume_row(ctx, "-", "-", "-", "-", std::nullopt,
                         std::format("FindFirstVolumeW failed: {}", ::GetLastError()));
        mark_result_partial(ctx, "windows:volume_enum",
                            std::format("FindFirstVolumeW failed: {}", ::GetLastError()));
        return 0;
    }

    bool any_extent_failure = false;
    for (;;) {
        std::wstring vol = volume;
        const std::string vol_utf8 = yuzu::win::from_wide(vol.c_str());

        // Mount points served by this volume. A volume with no letter and no
        // mount point is reported with "-" rather than omitted -- it still
        // occupies a physical drive, which is what this action is about.
        std::string mounts = "-";
        DWORD needed = 0;
        ::GetVolumePathNamesForVolumeNameW(vol.c_str(), nullptr, 0, &needed);
        if (needed > 1) {
            std::vector<wchar_t> buf(needed, L'\0');
            if (::GetVolumePathNamesForVolumeNameW(vol.c_str(), buf.data(), needed, &needed)) {
                std::string joined;
                for (const wchar_t* p = buf.data(); *p; p += ::wcslen(p) + 1) {
                    if (!joined.empty()) joined += ',';
                    joined += yuzu::win::from_wide(p);
                }
                if (!joined.empty()) mounts = joined;
            }
        }

        // THE JOIN: which physical drives back this volume. CreateFileW wants
        // the volume path WITHOUT its trailing backslash.
        std::string devices = "-";
        std::optional<std::uint64_t> total;
        std::wstring root = vol;
        if (!root.empty() && root.back() == L'\\') root.pop_back();
        ScopedFileHandle vh{::CreateFileW(root.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                          nullptr, OPEN_EXISTING, 0, nullptr)};
        if (vh.valid()) {
            // A spanned or striped volume touches several drives, so the reply
            // is variable-length; size it for a generous extent count rather
            // than assuming one.
            constexpr DWORD kMaxExtents = 32;
            std::vector<BYTE> buf(sizeof(VOLUME_DISK_EXTENTS) +
                                  (kMaxExtents - 1) * sizeof(DISK_EXTENT));
            DWORD returned = 0;
            if (::DeviceIoControl(vh.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0,
                                  buf.data(), static_cast<DWORD>(buf.size()), &returned, nullptr) &&
                returned >= sizeof(VOLUME_DISK_EXTENTS)) {
                const auto* ext = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(buf.data());
                const DWORD n = ext->NumberOfDiskExtents;
                // NumberOfDiskExtents is device-supplied; bound it against what
                // was actually returned before indexing.
                const std::size_t max_fit =
                    (returned - offsetof(VOLUME_DISK_EXTENTS, Extents)) / sizeof(DISK_EXTENT);
                std::string joined;
                std::uint64_t bytes = 0;
                for (DWORD e = 0; e < n && e < max_fit; ++e) {
                    if (!joined.empty()) joined += ',';
                    joined += "PhysicalDrive" + std::to_string(ext->Extents[e].DiskNumber);
                    bytes += static_cast<std::uint64_t>(ext->Extents[e].ExtentLength.QuadPart);
                }
                if (!joined.empty()) {
                    devices = joined;
                    total = bytes;
                }
            } else {
                any_extent_failure = true;
            }
        } else {
            any_extent_failure = true;
        }

        write_volume_row(ctx, vol_utf8, mounts, devices, "-", total, "-");

        if (!::FindNextVolumeW(find.get(), volume, MAX_PATH)) {
            const DWORD err = ::GetLastError();
            if (err != ERROR_NO_MORE_FILES)
                mark_result_partial(ctx, "windows:volume_enum",
                                    std::format("FindNextVolumeW failed: {}", err));
            break;
        }
    }

    if (any_extent_failure)
        mark_result_partial(ctx, "windows:volume_extents",
                            "at least one volume did not report its disk extents; those rows name "
                            "no backing drive");
    return 0;
}

} // namespace yuzu::disk_actions

#endif // defined(_WIN32)
