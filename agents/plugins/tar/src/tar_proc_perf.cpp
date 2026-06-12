#include "tar_proc_perf.hpp"

#include "tar_collectors.hpp" // should_redact

#include <algorithm>
#include <cmath>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::tar {

namespace {

// Saturating delta for cumulative counters (the tar_perf idiom).
std::uint64_t delta(std::uint64_t prev, std::uint64_t cur) {
    return cur >= prev ? cur - prev : 0;
}

// (pid, create_time) identity key — PID alone is reused by the OS.
std::uint64_t proc_key(const ProcCounter& p) {
    // create_time's low bits are unique enough to disambiguate a reused PID;
    // a 64-bit mix keeps the map single-keyed.
    return (static_cast<std::uint64_t>(p.pid) << 32) ^
           static_cast<std::uint64_t>(p.create_time_100ns);
}

} // namespace

std::vector<ProcPerfSample> derive_proc_samples(const ProcSnapshot& prev,
                                                const ProcSnapshot& cur,
                                                const std::vector<std::string>& redaction) {
    std::vector<ProcPerfSample> out;
    if (!prev.valid || !cur.valid || cur.ncores <= 0)
        return out;
    const std::int64_t elapsed = cur.ts_epoch - prev.ts_epoch;
    if (elapsed <= 0)
        return out;

    // prev lookup by identity key. create_time must MATCH — a reused PID with
    // a different create_time finds no baseline and contributes 0 CPU this
    // interval rather than a garbage delta.
    std::unordered_map<std::uint64_t, std::uint64_t> prev_cpu;
    prev_cpu.reserve(prev.procs.size());
    for (const auto& p : prev.procs)
        prev_cpu[proc_key(p)] = p.cpu_100ns;

    // Aggregate by image name (app-level, the BRD row-22 unit).
    struct Agg {
        int instances{0};
        std::uint64_t cpu_delta{0};
        std::uint64_t ws{0};
    };
    std::unordered_map<std::string, Agg> by_name;
    for (const auto& p : cur.procs) {
        if (p.name.empty())
            continue; // Idle / unnameable kernel entries — never a row
        if (!redaction.empty() && should_redact(p.name, redaction))
            continue; // operator-redacted apps never appear in the warehouse
        auto& a = by_name[p.name];
        ++a.instances;
        a.ws += p.ws_bytes;
        if (auto it = prev_cpu.find(proc_key(p)); it != prev_cpu.end())
            a.cpu_delta += delta(it->second, p.cpu_100ns);
    }
    if (by_name.empty())
        return out;

    // Total machine capacity over the interval, in 100 ns units.
    const double capacity = static_cast<double>(elapsed) * 1.0e7 * cur.ncores;
    std::vector<ProcPerfSample> all;
    all.reserve(by_name.size());
    for (auto& [name, a] : by_name) {
        ProcPerfSample s;
        s.name = name;
        s.instances = a.instances;
        s.cpu_pct = std::clamp(static_cast<double>(a.cpu_delta) * 100.0 / capacity, 0.0, 100.0);
        s.ws_bytes = static_cast<std::int64_t>(a.ws);
        all.push_back(std::move(s));
    }

    // Union of top-N by CPU and top-N by working set.
    const auto n = static_cast<std::size_t>(kProcTopN);
    std::vector<std::size_t> idx(all.size());
    for (std::size_t i = 0; i < idx.size(); ++i)
        idx[i] = i;
    std::unordered_set<std::size_t> chosen;
    auto take_top = [&](auto cmp) {
        std::sort(idx.begin(), idx.end(), cmp);
        for (std::size_t i = 0; i < (std::min)(n, idx.size()); ++i)
            chosen.insert(idx[i]);
    };
    take_top([&](std::size_t a, std::size_t b) { return all[a].cpu_pct > all[b].cpu_pct; });
    take_top([&](std::size_t a, std::size_t b) { return all[a].ws_bytes > all[b].ws_bytes; });

    out.reserve(chosen.size());
    for (std::size_t i : chosen)
        out.push_back(std::move(all[i]));
    // Stable presentation order: CPU-heaviest first.
    std::sort(out.begin(), out.end(),
              [](const ProcPerfSample& a, const ProcPerfSample& b) {
                  return a.cpu_pct != b.cpu_pct ? a.cpu_pct > b.cpu_pct
                                                : a.ws_bytes > b.ws_bytes;
              });
    return out;
}

} // namespace yuzu::tar

// ── Impure shell: platform process-counter snapshot ──────────────────────────

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h> // SYSTEM_PROCESS_INFORMATION (public/partial), NTSTATUS

#include <cstddef>
#include <ctime>
#include <vector>

namespace yuzu::tar {

namespace {

// The REAL SystemProcessInformation entry layout. winternl.h's public struct
// hides CreateTime/UserTime/KernelTime inside Reserved1[48]; this is the
// stable documented-in-practice layout (phnt / ntdoc — unchanged since
// Vista). The static_asserts below pin our offsets to the fields winternl.h
// DOES expose, so any SDK divergence fails the build, not the fleet.
struct SysProcEntry {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    // trailing fields exist; NextEntryOffset walks past them safely
};
static_assert(offsetof(SysProcEntry, ImageName) ==
              offsetof(SYSTEM_PROCESS_INFORMATION, ImageName));
static_assert(offsetof(SysProcEntry, UniqueProcessId) ==
              offsetof(SYSTEM_PROCESS_INFORMATION, UniqueProcessId));
static_assert(offsetof(SysProcEntry, WorkingSetSize) ==
              offsetof(SYSTEM_PROCESS_INFORMATION, WorkingSetSize));

using NtQsiFn = NTSTATUS(WINAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);

// UTF-16 → UTF-8 for a counted (possibly unterminated) UNICODE_STRING.
std::string ucs_to_utf8(const UNICODE_STRING& u) {
    if (!u.Buffer || u.Length == 0)
        return {};
    const int wlen = static_cast<int>(u.Length / sizeof(WCHAR));
    const int need =
        ::WideCharToMultiByte(CP_UTF8, 0, u.Buffer, wlen, nullptr, 0, nullptr, nullptr);
    if (need <= 0)
        return {};
    std::string out(static_cast<std::size_t>(need), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, u.Buffer, wlen, out.data(), need, nullptr, nullptr);
    return out;
}

} // namespace

ProcSnapshot read_proc_counters() {
    ProcSnapshot snap;
    snap.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));

    static const NtQsiFn nt_qsi = []() -> NtQsiFn {
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<NtQsiFn>(
                           ::GetProcAddress(ntdll, "NtQuerySystemInformation"))
                     : nullptr;
    }();
    if (!nt_qsi)
        return snap; // valid stays false

    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    snap.ncores = static_cast<int>(si.dwNumberOfProcessors);

    // Buffer-growth loop: the process list changes between the size probe and
    // the fill, so re-ask with headroom until it fits (bounded attempts).
    std::vector<unsigned char> buf(1 << 18); // 256 KiB start
    for (int attempt = 0; attempt < 6; ++attempt) {
        ULONG needed = 0;
        const NTSTATUS st =
            nt_qsi(SystemProcessInformation, buf.data(), static_cast<ULONG>(buf.size()), &needed);
        if (st == kStatusInfoLengthMismatch) {
            buf.resize(static_cast<std::size_t>(needed) + (1 << 16));
            continue;
        }
        if (st != 0)
            return snap; // any other failure: valid stays false
        break;
    }

    std::size_t off = 0;
    while (off + sizeof(SysProcEntry) <= buf.size()) {
        const auto* e = reinterpret_cast<const SysProcEntry*>(buf.data() + off);
        const auto pid =
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(e->UniqueProcessId));
        if (pid != 0) { // skip Idle — its "CPU" is the absence of work
            ProcCounter p;
            p.pid = pid;
            p.create_time_100ns = e->CreateTime.QuadPart;
            p.cpu_100ns = static_cast<std::uint64_t>(e->KernelTime.QuadPart) +
                          static_cast<std::uint64_t>(e->UserTime.QuadPart);
            p.ws_bytes = static_cast<std::uint64_t>(e->WorkingSetSize);
            p.name = ucs_to_utf8(e->ImageName);
            if (p.name.empty() && pid == 4)
                p.name = "System"; // the kernel: real working set, no image name
            snap.procs.push_back(std::move(p));
        }
        if (e->NextEntryOffset == 0)
            break;
        off += e->NextEntryOffset;
    }
    snap.valid = true;
    return snap;
}

} // namespace yuzu::tar

#else // !_WIN32 — Linux (/proc/[pid]/stat) and macOS (proc_pid_rusage) are kPlanned

#include <ctime>

namespace yuzu::tar {

ProcSnapshot read_proc_counters() {
    ProcSnapshot snap;
    snap.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));
    return snap; // valid=false — collect_perf records nothing on this platform yet
}

} // namespace yuzu::tar

#endif
