#include "tar_perf.hpp"

#include <algorithm>
#include <ctime>

namespace yuzu::tar {

namespace {

// Saturating delta for cumulative counters: a regression reads as "no data"
// (0), never as a giant unsigned wrap.
std::uint64_t delta(std::uint64_t prev, std::uint64_t cur) {
    return cur >= prev ? cur - prev : 0;
}

double clamp_pct(double v) { return std::clamp(v, 0.0, 100.0); }

} // namespace

PerfSample derive_sample(const PerfCounters& prev, const PerfCounters& cur) {
    PerfSample s;
    if (!prev.valid || !cur.valid)
        return s;
    const std::int64_t elapsed = cur.ts_epoch - prev.ts_epoch;
    if (elapsed <= 0)
        return s;
    // CPU counter regression = reboot/reset between samples — the whole
    // baseline is gone, so the sample is invalid (next tick re-baselines).
    if (cur.cpu_idle < prev.cpu_idle || cur.cpu_kernel < prev.cpu_kernel ||
        cur.cpu_user < prev.cpu_user)
        return s;
    s.valid = true;

    // CPU: kernel includes idle, so total = kernel + user, busy = total - idle.
    const std::uint64_t idle_d = cur.cpu_idle - prev.cpu_idle;
    const std::uint64_t total_d =
        (cur.cpu_kernel - prev.cpu_kernel) + (cur.cpu_user - prev.cpu_user);
    if (total_d > 0 && total_d >= idle_d)
        s.cpu_pct = clamp_pct(100.0 * static_cast<double>(total_d - idle_d) /
                              static_cast<double>(total_d));

    // Memory: instantaneous from the current reading.
    if (cur.mem_total_bytes > 0)
        s.mem_used_pct = clamp_pct(
            100.0 * static_cast<double>(cur.mem_total_bytes - (std::min)(cur.mem_avail_bytes,
                                                                         cur.mem_total_bytes)) /
            static_cast<double>(cur.mem_total_bytes));
    if (cur.commit_limit_bytes > 0)
        s.commit_pct = clamp_pct(100.0 * static_cast<double>(cur.commit_total_bytes) /
                                 static_cast<double>(cur.commit_limit_bytes));

    // Disk: per-domain degrade — both readings must have disk data; a
    // regression (hotplug/reset) zeroes this domain for one interval via the
    // saturating delta.
    if (prev.disk_valid && cur.disk_valid) {
        s.disk_read_bps = static_cast<std::int64_t>(
            delta(prev.disk_read_bytes, cur.disk_read_bytes) /
            static_cast<std::uint64_t>(elapsed));
        s.disk_write_bps = static_cast<std::int64_t>(
            delta(prev.disk_write_bytes, cur.disk_write_bytes) /
            static_cast<std::uint64_t>(elapsed));
        const std::uint64_t reads_d = delta(prev.disk_reads, cur.disk_reads);
        const std::uint64_t writes_d = delta(prev.disk_writes, cur.disk_writes);
        if (reads_d > 0)
            s.disk_read_lat_us = static_cast<std::int64_t>(
                delta(prev.disk_read_time_100ns, cur.disk_read_time_100ns) / reads_d / 10);
        if (writes_d > 0)
            s.disk_write_lat_us = static_cast<std::int64_t>(
                delta(prev.disk_write_time_100ns, cur.disk_write_time_100ns) / writes_d / 10);
    }

    // Network: interface churn (a VPN adapter vanishing) shrinks the summed
    // counters — the saturating delta records one 0-rate interval and the
    // next tick self-corrects, rather than poisoning the whole row.
    s.net_rx_bps = static_cast<std::int64_t>(delta(prev.net_rx_bytes, cur.net_rx_bytes) /
                                             static_cast<std::uint64_t>(elapsed));
    s.net_tx_bps = static_cast<std::int64_t>(delta(prev.net_tx_bytes, cur.net_tx_bytes) /
                                             static_cast<std::uint64_t>(elapsed));
    return s;
}

} // namespace yuzu::tar

// ── Impure shell: platform counter reads ─────────────────────────────────────

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <winsock2.h> // must precede windows.h; netioapi.h needs its typedefs
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h> // GetIfTable2 / MIB_IF_TABLE2 (64-bit octet counters)
#include <winioctl.h> // IOCTL_DISK_PERFORMANCE, DISK_PERFORMANCE
#include <psapi.h>    // GetPerformanceInfo (commit charge)
// clang-format on

#include <string>

namespace yuzu::tar {

namespace {

std::uint64_t ft_to_u64(const FILETIME& ft) {
    return (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

// Sum IOCTL_DISK_PERFORMANCE over \\.\PhysicalDrive0..31. A missing index or
// an unsupported disk (some virtual disks) is skipped; disk_valid only when
// at least one disk responded. Open with zero access rights — the IOCTL
// needs none, so this works for the unprivileged dev agent too.
void read_disks(PerfCounters& c) {
    for (int n = 0; n < 32; ++n) {
        const std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(n);
        HANDLE h = ::CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            continue;
        DISK_PERFORMANCE perf{};
        DWORD bytes = 0;
        if (::DeviceIoControl(h, IOCTL_DISK_PERFORMANCE, nullptr, 0, &perf, sizeof(perf),
                              &bytes, nullptr)) {
            c.disk_valid = true;
            c.disk_read_bytes += static_cast<std::uint64_t>(perf.BytesRead.QuadPart);
            c.disk_write_bytes += static_cast<std::uint64_t>(perf.BytesWritten.QuadPart);
            c.disk_read_time_100ns += static_cast<std::uint64_t>(perf.ReadTime.QuadPart);
            c.disk_write_time_100ns += static_cast<std::uint64_t>(perf.WriteTime.QuadPart);
            c.disk_reads += perf.ReadCount;
            c.disk_writes += perf.WriteCount;
        }
        ::CloseHandle(h);
    }
}

void read_network(PerfCounters& c) {
    MIB_IF_TABLE2* table = nullptr;
    if (::GetIfTable2(&table) != NO_ERROR || !table)
        return;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IF_ROW2& row = table->Table[i];
        if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        c.net_rx_bytes += row.InOctets;  // 64-bit — no wrap concern
        c.net_tx_bytes += row.OutOctets;
    }
    ::FreeMibTable(table);
}

} // namespace

PerfCounters read_perf_counters() {
    PerfCounters c;
    c.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));

    FILETIME idle{}, kernel{}, user{};
    if (!::GetSystemTimes(&idle, &kernel, &user))
        return c; // valid stays false
    c.cpu_idle = ft_to_u64(idle);
    c.cpu_kernel = ft_to_u64(kernel);
    c.cpu_user = ft_to_u64(user);

    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    if (!::GlobalMemoryStatusEx(&mem))
        return c;
    c.mem_total_bytes = mem.ullTotalPhys;
    c.mem_avail_bytes = mem.ullAvailPhys;

    PERFORMANCE_INFORMATION pi{};
    pi.cb = sizeof(pi);
    if (::GetPerformanceInfo(&pi, sizeof(pi))) {
        c.commit_total_bytes = static_cast<std::uint64_t>(pi.CommitTotal) * pi.PageSize;
        c.commit_limit_bytes = static_cast<std::uint64_t>(pi.CommitLimit) * pi.PageSize;
    }

    c.valid = true; // CPU + memory are the core reads; disk/net degrade separately
    read_disks(c);
    read_network(c);
    return c;
}

} // namespace yuzu::tar

#else // !_WIN32 — Linux (/proc) and macOS (host_statistics) are kPlanned

namespace yuzu::tar {

PerfCounters read_perf_counters() {
    PerfCounters c;
    c.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));
    return c; // valid=false — collect_perf records nothing on this platform yet
}

} // namespace yuzu::tar

#endif
