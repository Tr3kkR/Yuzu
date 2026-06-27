#include "tar_proc_perf.hpp"

#include "tar_collectors.hpp" // should_redact

#include <algorithm>
#include <cmath>
#include <format>
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
    return proc_identity(p.pid, p.create_time_100ns);
}

} // namespace

std::uint64_t proc_identity(std::uint32_t pid, std::int64_t create_time_100ns) {
    // PID in the high 32 bits XOR'd with the FULL 64-bit create_time; a
    // collision needs two procs whose create_time high-dword aligns with a
    // reused PID — astronomically rare, and at worst costs one interval of CPU
    // mis-attribution for one app row.
    return (static_cast<std::uint64_t>(pid) << 32) ^
           static_cast<std::uint64_t>(create_time_100ns);
}

std::string format_file_version(std::uint32_t ms, std::uint32_t ls) {
    return std::format("{}.{}.{}.{}", (ms >> 16) & 0xffffu, ms & 0xffffu,
                       (ls >> 16) & 0xffffu, ls & 0xffffu);
}

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

    // Aggregate by image name (app-level, the BRD row-22 unit). `rep_*` track
    // the largest-working-set instance — the representative whose on-disk image
    // version stands in for the app this tick (resolved later, off the lock).
    struct Agg {
        int instances{0};
        std::uint64_t cpu_delta{0};
        std::uint64_t ws{0};
        std::uint32_t rep_pid{0};
        std::int64_t rep_create_time{0};
        std::uint64_t rep_ws{0};
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
        if (a.rep_pid == 0 || p.ws_bytes > a.rep_ws) {
            a.rep_ws = p.ws_bytes;
            a.rep_pid = p.pid;
            a.rep_create_time = p.create_time_100ns;
        }
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
        s.rep_pid = a.rep_pid;
        s.rep_create_time_100ns = a.rep_create_time;
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
#include <winver.h>   // GetFileVersionInfoW / VerQueryValueW / VS_FIXEDFILEINFO

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
// These asserts pin only the fields winternl.h PUBLICLY exposes — all of which
// sit AFTER the `Reserved1[48]` block. CreateTime/UserTime/KernelTime (the CPU
// fields we read) live INSIDE that reserved region, so they CANNOT be
// offsetof-checked; their offsets rely on the documented, Vista-stable layout
// of the reserved bytes (gov cross-platform S1). Pinning ImageName's absolute
// offset (56 on x64) transitively anchors the tail, and walking by
// NextEntryOffset insulates against trailing-field growth across Win10/11/Server
// SKUs — so any layout drift that would matter trips one of these.
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

// RAII for a process HANDLE — CloseHandle on every exit path (the OpenProcess
// in resolve_one_version has several early returns; a manual close would leak).
struct HandleGuard {
    HANDLE h{nullptr};
    explicit HandleGuard(HANDLE handle) : h{handle} {}
    ~HandleGuard() {
        if (h && h != INVALID_HANDLE_VALUE)
            ::CloseHandle(h);
    }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    explicit operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
};

// Resolve ONE process's on-disk file version, or "" on any failure. The path is
// read only to feed GetFileVersionInfo and is discarded immediately (it can
// carry a user-profile dir — privacy). `create_time_100ns` is the snapshot's
// CreateTime; it MUST match the live process before any path/version read, or a
// reused PID would get another process's version attributed.
std::string resolve_one_version(std::uint32_t pid, std::int64_t create_time_100ns) {
    HandleGuard proc{::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!proc)
        return {}; // protected/system process or gone — version stays ""

    // PID-reuse guard FIRST: FILETIME-to-FILETIME (100 ns since 1601), never
    // against the Unix-seconds ts_epoch.
    FILETIME ft_create{}, ft_exit{}, ft_kernel{}, ft_user{};
    if (!::GetProcessTimes(proc.h, &ft_create, &ft_exit, &ft_kernel, &ft_user))
        return {};
    ULARGE_INTEGER created{};
    created.LowPart = ft_create.dwLowDateTime;
    created.HighPart = ft_create.dwHighDateTime;
    if (static_cast<std::int64_t>(created.QuadPart) != create_time_100ns)
        return {}; // PID was reused since the snapshot — refuse before reading

    WCHAR path[MAX_PATH * 2];
    DWORD path_len = static_cast<DWORD>(std::size(path));
    if (!::QueryFullProcessImageNameW(proc.h, 0, path, &path_len))
        return {};

    DWORD ignored = 0;
    const DWORD info_size = ::GetFileVersionInfoSizeW(path, &ignored);
    if (info_size == 0)
        return {}; // no version resource (common for many non-vendor exes)
    std::vector<unsigned char> info(info_size); // RAII buffer
    if (!::GetFileVersionInfoW(path, 0, info_size, info.data()))
        return {};
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT ffi_len = 0;
    if (!::VerQueryValueW(info.data(), L"\\", reinterpret_cast<LPVOID*>(&ffi), &ffi_len) ||
        !ffi || ffi_len < sizeof(VS_FIXEDFILEINFO))
        return {};
    // An all-zero fixed version is the "no real version" case — return "" so it
    // shares the single unknown-version bucket with the crash side's canon_version
    // ("0.0.0.0" → ""), keeping the (name, version) join consistent across perf
    // and stability. (DEX app-perf-over-time slice 2b.)
    if (ffi->dwFileVersionMS == 0 && ffi->dwFileVersionLS == 0)
        return {};
    return format_file_version(ffi->dwFileVersionMS, ffi->dwFileVersionLS);
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
    // `ok` is load-bearing: only a successful (st==0) fill is walkable. If all
    // attempts return STATUS_INFO_LENGTH_MISMATCH, the buffer holds partial
    // kernel writes AND each resize() moved storage, so every kernel-written
    // ImageName.Buffer (an absolute pointer INTO the pre-resize allocation) now
    // dangles — walking it would be a use-after-free heap read (gov cpp-safety
    // BLOCKING). Bail with valid=false instead.
    std::vector<unsigned char> buf(1 << 18); // 256 KiB start
    bool ok = false;
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
        ok = true;
        break;
    }
    if (!ok)
        return snap; // never successfully filled — buffer contents are undefined

    const unsigned char* base = buf.data();
    const unsigned char* end = base + buf.size();
    std::size_t off = 0;
    while (off + sizeof(SysProcEntry) <= buf.size()) {
        const auto* e = reinterpret_cast<const SysProcEntry*>(base + off);
        const auto pid =
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(e->UniqueProcessId));
        if (pid != 0) { // skip Idle — its "CPU" is the absence of work
            ProcCounter p;
            p.pid = pid;
            p.create_time_100ns = e->CreateTime.QuadPart;
            p.cpu_100ns = static_cast<std::uint64_t>(e->KernelTime.QuadPart) +
                          static_cast<std::uint64_t>(e->UserTime.QuadPart);
            p.ws_bytes = static_cast<std::uint64_t>(e->WorkingSetSize);
            // Defence-in-depth: only read ImageName if its (Buffer, Length)
            // span lies wholly within the buffer. The kernel writes Buffer as
            // an absolute pointer into `buf`; a corrupt/forged length must never
            // make ucs_to_utf8 read out of bounds.
            const auto* nb = reinterpret_cast<const unsigned char*>(e->ImageName.Buffer);
            if (nb && e->ImageName.Length > 0 && nb >= base && nb + e->ImageName.Length <= end)
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

void resolve_proc_versions(std::vector<ProcPerfSample>& samples,
                           std::unordered_map<std::uint64_t, std::string>& cache) {
    // Rewrite the cache to this tick's live top-N: a process keeps its version
    // (resolved once at first sighting) while it stays in the set, and the cache
    // can never grow past <= 2N entries. A failed resolve is cached as "" too,
    // so a protected process is not re-OpenProcess'd every tick it survives.
    std::unordered_map<std::uint64_t, std::string> next;
    next.reserve(samples.size());
    for (auto& s : samples) {
        if (s.rep_pid == 0)
            continue; // no representative instance — leave version ""
        const auto key = proc_identity(s.rep_pid, s.rep_create_time_100ns);
        if (auto it = cache.find(key); it != cache.end())
            s.version = it->second;
        else
            s.version = resolve_one_version(s.rep_pid, s.rep_create_time_100ns);
        next.emplace(key, s.version);
    }
    cache.swap(next);
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

// No per-process version source yet (the Linux/macOS per-app collectors are
// kPlanned). Leave every version "" without touching the cache.
void resolve_proc_versions(std::vector<ProcPerfSample>& /*samples*/,
                           std::unordered_map<std::uint64_t, std::string>& /*cache*/) {}

} // namespace yuzu::tar

#endif
