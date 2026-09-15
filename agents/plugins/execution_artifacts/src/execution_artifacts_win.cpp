/**
 * execution_artifacts_win.cpp — Windows leg entry points for the
 * execution_artifacts plugin (ShimCache, Amcache InventoryApplicationFile,
 * Prefetch). Implements the three declarations in execution_artifacts_legs.hpp
 * (P31); every parser this file calls into is the pure, OS-free
 * execution_artifacts_parsers.hpp — this TU owns ONLY the Win32 I/O that
 * gathers the raw bytes those parsers consume.
 *
 * A1's the-rig probe findings (2026-09-06,
 * tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md), quoted
 * verbatim for the two probes this package's legs consume (its third probe,
 * ITaskService/WMI, belongs to the autoruns package and is not used here):
 *
 * PROBE 1 (RtlDecompressBufferEx / MAM prefetch decompression) — "GetProc-
 * Address(GetModuleHandleW(L"ntdll"), "RtlGetCompressionWorkSpaceSize") and
 * "RtlDecompressBufferEx" both resolved to non-null addresses in every run
 * (admin and LocalSystem). ... All four decompression attempts returned
 * STATUS_SUCCESS (0x00000000) for both RtlGetCompressionWorkSpaceSize
 * (workspace size 166495 bytes in every case, format
 * COMPRESSION_FORMAT_XPRESS_HUFF = 4, engine standard) and
 * RtlDecompressBufferEx. Every decompressed payload's bytes 4-7 read 'SCCA'
 * as expected for a valid prefetch header."
 *
 * PROBE 2 (RegLoadAppKeyW / Amcache.hve) — "Copy-Item of
 * C:\Windows\appcompat\Programs\Amcache.hve succeeded as a plain copy in the
 * admin session (SeBackupPrivilege already Enabled) -- no sharing violation
 * was hit, so the CreateFile(FILE_SHARE_READ|WRITE|DELETE,
 * FILE_FLAG_BACKUP_SEMANTICS) + SeBackupPrivilege fallback path was never
 * exercised; it was not needed to obtain the copy. ... Key finding for
 * P32's locking design: RegLoadAppKeyW does NOT require SeBackupPrivilege.
 * It succeeded (LSTATUS 0x00000000 / ERROR_SUCCESS) with the privilege
 * explicitly disabled via AdjustTokenPrivileges, in both the admin session
 * and under LocalSystem. RegLoadAppKeyW loads a private, process-scoped
 * hive copy and does not go through the backup/restore privilege check that
 * RegLoadKey/RegRestoreKey do." (8889 real InventoryApplicationFile subkeys
 * in every one of the four probe runs.)
 *
 * Consequences for this file's design:
 *   - The Amcache copy tries plain CopyFileW FIRST; the SeBackupPrivilege +
 *     CreateFileW(FILE_FLAG_BACKUP_SEMANTICS) fallback is dead code on
 *     probe-representative hardware (unexercised there) but is kept for a
 *     host where the hive genuinely is exclusively locked (this package's
 *     spec: "not guaranteed on every host").
 *   - RegLoadAppKeyW itself never needs a PrivilegeScope.
 *
 * HOLD-TIME BOUND (acceptance criterion): collect_amcache's single
 * offline_hive_mutex() hold spans PrivilegeScope construction (only taken on
 * the ERROR_SHARING_VIOLATION fallback path) through the copy, RegLoadAppKeyW,
 * enumeration (capped at kAmcacheMaxSubkeys = 20000 registry reads, each
 * itself bounded by win_profiles.hpp's kMaxRegValueBytes = 1 MiB), and
 * RegCloseKey. Every step in that span is bounded LOCAL disk/registry I/O
 * (copy capped at kAmcacheMaxBytes = 256 MiB) — never network, never user
 * input — so the hold time is bounded by those caps, not open-ended.
 *
 * PROCESS-TOKEN DISCIPLINE (win_profiles.hpp:416-432): PrivilegeScope mutates
 * the PROCESS token, so this file follows with_user_hive's own discipline
 * (win_profiles.hpp:479-535) exactly — the privilege-bearing sequence is
 * fully nested inside ONE offline_hive_mutex() lock_guard, never split
 * across two.
 *
 * ShimCache's local blob reader mirrors read_reg_value's size-then-fill +
 * changed_during_read bounded-retry idiom (win_profiles.hpp:560-620) at a
 * LOCAL 16 MiB cap — win_profiles.hpp's own kMaxRegValueBytes (1 MiB,
 * win_profiles.hpp:61) is a SHARED constant other callers rely on staying at
 * 1 MiB and is never raised here.
 *
 * Every entry point is wrapped in try/catch(...) -> constrained|internal_error
 * (this package's spec) since std::bad_alloc/std::length_error are always
 * possible around the untrusted-size-driven allocations below, even though
 * every size that reaches an allocation is bounds-checked first.
 *
 * Never emits file contents, never touches Layout.ini (the Prefetch
 * enumeration globs *.pf only), no VSS/esentutl/spawn.
 */

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h> // NTSTATUS (confined_fs_win.cpp precedent)
#include <sddl.h>     // ConvertStringSecurityDescriptorToSecurityDescriptorW (amcache_dest_dir DACL)

#include <win_profiles.hpp> // RegKey, PrivilegeScope, offline_hive_mutex, read_reg_value,
                            // enumerate_value_names, to_wide/from_wide

#include "execution_artifacts_legs.hpp"
#include "execution_artifacts_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <yuzu/agent/offline_hive_mutex.hpp>
#include <yuzu/string_utils.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <format>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::execution_artifacts {

namespace {

// ── shared helpers ──────────────────────────────────────────────────────

/// Writes a `constrained|<token>` row, sets the CC-07 typed status, and
/// returns the leg's exit code for that status (1 — the legs.hpp contract:
/// 0 only on YUZU_RESULT_STATUS_OK).
int emit_constrained(yuzu::CommandContext& ctx, const std::string& token) {
    ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL, token);
    ctx.write_output("constrained|" + token);
    return 1;
}

std::string ntstatus_token(NTSTATUS status) {
    return std::format("ntstatus_{:x}", static_cast<uint32_t>(status));
}

/// Classifies a Win32 GetLastError() value from an Amcache hive copy
/// attempt into a diagnostic token, mirroring ShimCache's reg_<code> and
/// Prefetch's ntstatus_<hex> conventions in this same file. Only
/// ERROR_SHARING_VIOLATION maps to "hive_locked" -- every other failure
/// (disk full, access denied, bad path, etc.) gets its own win32_<code>
/// token so an operator isn't sent down the "it's locked" runbook for an
/// unrelated fault.
std::string amcache_copy_error_token(DWORD err) {
    if (err == ERROR_SHARING_VIOLATION)
        return "hive_locked";
    return "win32_" + std::to_string(err);
}

// Single-owner RAII for a Win32 HANDLE, released via `CloseFn` on
// destruction/move/reset. Both `nullptr` and `INVALID_HANDLE_VALUE` are
// treated as "empty" -- CreateFileW's failure sentinel is the latter, not
// the former, and every raw HANDLE in this file (the AmCache backup-copy
// src/dst, the Prefetch find handle, the per-file read handle) previously
// relied on a hand-matched CloseHandle/FindClose on every return path, which
// is exactly the shape that leaks on an exception thrown between open and
// close (this file's own header banner: parsers can throw std::bad_alloc on
// an untrusted size). Mirrors agents/core/src/guard_win_handle.hpp's
// ScopedWinHandle shape -- that header is core-internal and not on this
// plugin's include path, so this is a local specialisation rather than a
// cross-module include, same precedent as tar_netconn_win.cpp's EvtGuard.
template <void (*CloseFn)(HANDLE)>
class ScopedWinHandle {
public:
    ScopedWinHandle() = default;
    explicit ScopedWinHandle(HANDLE h) : h_(norm(h)) {}
    ~ScopedWinHandle() { reset(); }

    ScopedWinHandle(const ScopedWinHandle&) = delete;
    ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;
    ScopedWinHandle(ScopedWinHandle&& other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    ScopedWinHandle& operator=(ScopedWinHandle&& other) noexcept {
        if (this != &other) {
            reset();
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }

    HANDLE get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }
    void reset(HANDLE h = nullptr) {
        if (h_)
            CloseFn(h_);
        h_ = norm(h);
    }

private:
    static HANDLE norm(HANDLE h) {
        return (h == nullptr || h == INVALID_HANDLE_VALUE) ? nullptr : h;
    }
    HANDLE h_ = nullptr;
};

inline void close_handle_(HANDLE h) { ::CloseHandle(h); }
inline void find_close_(HANDLE h) { ::FindClose(h); }

using ScopedHandle = ScopedWinHandle<&close_handle_>;     ///< CreateFileW
using ScopedFindHandle = ScopedWinHandle<&find_close_>;   ///< FindFirstFileW

// ── ShimCache ────────────────────────────────────────────────────────────

constexpr wchar_t kShimCacheSubkey[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache";
constexpr wchar_t kShimCacheValueName[] = L"AppCompatCache";

// LOCAL bound, deliberately distinct from win_profiles.hpp's shared
// kMaxRegValueBytes (1 MiB, win_profiles.hpp:61) -- ShimCache blobs are
// legitimately larger than the general-purpose registry-value cap that
// constant protects, and raising the shared constant would loosen every
// other caller of read_reg_value in the tree. See this package's spec.
constexpr DWORD kShimCacheMaxBytes = 16u * 1024u * 1024u; // 16 MiB

enum class ShimBlobStatus { ok, not_found, oversized, changed_during_read };

/// Reads the AppCompatCache value under `key`, bounded at kShimCacheMaxBytes.
/// Same size-then-fill + bounded-growth-retry idiom as win_profiles.hpp's
/// read_reg_value (win_profiles.hpp:560-620), reimplemented locally rather
/// than reusing that function because the cap differs (16 MiB here vs its
/// shared 1 MiB) and read_reg_value's cap is not a parameter. `out_rc`
/// carries the last LSTATUS seen, for the not_found case's `reg_<status>`
/// token.
ShimBlobStatus read_shimcache_blob(HKEY key, std::vector<uint8_t>& out, LSTATUS& out_rc) {
    DWORD type = 0, size = 0;
    out_rc = RegQueryValueExW(key, kShimCacheValueName, nullptr, &type, nullptr, &size);
    if (out_rc != ERROR_SUCCESS)
        return ShimBlobStatus::not_found;

    bool exceeds_cap = size > kShimCacheMaxBytes;
    if (exceeds_cap)
        size = kShimCacheMaxBytes;

    // Never a zero-length allocation (win_profiles.hpp P2-N5): an empty
    // data() pointer would switch RegQueryValueExW into size-query mode
    // regardless of *lpcbData, misreading a value that grew concurrently.
    std::vector<BYTE> data(size > 0 ? size : 1);
    DWORD capacity = static_cast<DWORD>(data.size());
    LSTATUS read_rc =
        RegQueryValueExW(key, kShimCacheValueName, nullptr, &type, data.data(), &capacity);
    size = capacity;

    constexpr int kMaxGrowthRetries = 3;
    for (int attempt = 0; read_rc == ERROR_MORE_DATA && !exceeds_cap && attempt < kMaxGrowthRetries;
        ++attempt) {
        DWORD fresh_size = 0;
        if (RegQueryValueExW(key, kShimCacheValueName, nullptr, &type, nullptr, &fresh_size) !=
            ERROR_SUCCESS) {
            read_rc = ERROR_FILE_NOT_FOUND;
            break;
        }
        exceeds_cap = fresh_size > kShimCacheMaxBytes;
        size = exceeds_cap ? kShimCacheMaxBytes : fresh_size;
        data.assign(size > 0 ? size : 1, BYTE{0});
        capacity = static_cast<DWORD>(data.size());
        read_rc =
            RegQueryValueExW(key, kShimCacheValueName, nullptr, &type, data.data(), &capacity);
        size = capacity;
    }
    out_rc = read_rc;
    if (read_rc == ERROR_MORE_DATA && !exceeds_cap)
        return ShimBlobStatus::changed_during_read;
    if (read_rc != ERROR_SUCCESS)
        return exceeds_cap ? ShimBlobStatus::oversized : ShimBlobStatus::not_found;

    out.assign(data.begin(), data.begin() + size);
    return ShimBlobStatus::ok;
}

// ── Amcache ──────────────────────────────────────────────────────────────

constexpr wchar_t kAmcacheSourceHve[] = L"C:\\Windows\\appcompat\\Programs\\Amcache.hve";
constexpr uint64_t kAmcacheMaxBytes = 256ull * 1024 * 1024; // 256 MiB
constexpr DWORD kAmcacheMaxSubkeys = 20000;

// This leg receives only a CommandContext, not the PluginContext that would
// carry `agent.data_dir` (that config plumbing lives in
// execution_artifacts_plugin.cpp, P31's file, out of this package's scope)
// -- so unlike tar_plugin.cpp's init()-time cache (tar_plugin.cpp:565-580)
// this is always that same logic's PLATFORM-FALLBACK arm (the literal
// C:/ProgramData/yuzu/agent path used when agent.data_dir is empty),
// resolved once via a magic static (confined_fs_win.cpp's
// resolve_ntcreatefile precedent) rather than recomputed per call.
const std::wstring& amcache_dest_dir() {
    static const std::wstring dir = L"C:\\ProgramData\\yuzu\\agent\\execution_artifacts";
    return dir;
}

std::wstring amcache_temp_path() {
    return amcache_dest_dir() + L"\\amcache_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
           std::to_wstring(GetTickCount64()) + L".hve";
}

/// Process-wide count of persistent temp-hive cleanup failures (e.g. an AV
/// lock holding the file open past this action's own lifetime) across every
/// TempHiveCleanup instance in this plugin process. There is no cap or
/// alert path on the underlying accumulation -- that residual is unchanged
/// -- but a repeated failure is now at least observable via this counter's
/// value in the log line below, rather than each occurrence being an
/// isolated, uncorrelated `note|` row with no way to tell "happened once"
/// from "happening every run".
std::atomic<uint64_t> g_temp_cleanup_failed_total{0};

/// Deletes every path added, on scope exit, regardless of which return path
/// this function's caller takes (this package's spec: "temp copies always
/// deleted (scope guard)"). A deletion failure is logged via a `note|`
/// row, never silently dropped, but never fails the action itself -- the
/// action's own result was already decided by the time cleanup runs.
class TempHiveCleanup {
public:
    explicit TempHiveCleanup(yuzu::CommandContext& ctx) : ctx_(ctx) {}
    void add(std::wstring path) { paths_.push_back(std::move(path)); }

    TempHiveCleanup(const TempHiveCleanup&) = delete;
    TempHiveCleanup& operator=(const TempHiveCleanup&) = delete;

    ~TempHiveCleanup() {
        for (const auto& p : paths_) {
            if (!DeleteFileW(p.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
                const uint64_t total =
                    g_temp_cleanup_failed_total.fetch_add(1, std::memory_order_relaxed) + 1;
                // Diagnostics (allocation inside write_output/spdlog) must
                // never be allowed to throw out of a destructor -- that
                // would call std::terminate and kill the agent process
                // mid-unwind, losing every remaining cleanup and the
                // in-flight result this destructor was trying to report
                // around. The deletion attempt and failure counter above
                // are unconditional; only the diagnostic emission itself is
                // best-effort.
                try {
                    ctx_.write_output("note|temp_cleanup_failed");
                    spdlog::warn("execution_artifacts: temp hive cleanup failed ({} total this "
                                 "process)",
                                 total);
                } catch (...) {
                }
            }
        }
    }

private:
    yuzu::CommandContext& ctx_;
    std::vector<std::wstring> paths_;
};

/// The ERROR_SHARING_VIOLATION fallback: SeBackupPrivilege + backup-semantics
/// read, chunked into `dest`. Unexercised on A1's probe host (plain CopyFileW
/// always sufficed there — see the file banner) but kept for a host where the
/// hive genuinely is exclusively held elsewhere. Returns a token naming the
/// failure on any error; empty string on success.
std::string copy_amcache_via_backup_semantics(const wchar_t* dest) {
    // Kept inside the SAME offline_hive_mutex hold the caller already took --
    // this function is only ever called from inside that lock_guard's scope.
    yuzu::win::PrivilegeScope backup_priv(L"SeBackupPrivilege");
    (void)backup_priv; // ok() is not gated on -- CreateFileW below is the real test;
                       // a host that does not need the privilege for this
                       // particular file (probe finding) still benefits from a
                       // best-effort enable.

    ScopedHandle src(CreateFileW(kAmcacheSourceHve, GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!src)
        return amcache_copy_error_token(GetLastError());

    ScopedHandle dst(CreateFileW(dest, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!dst)
        return amcache_copy_error_token(GetLastError());

    std::vector<uint8_t> buf(1u * 1024 * 1024);
    uint64_t total = 0;
    bool ok = true;
    std::string token;
    for (;;) {
        DWORD read_bytes = 0;
        if (!ReadFile(src.get(), buf.data(), static_cast<DWORD>(buf.size()), &read_bytes,
                      nullptr)) {
            ok = false;
            token = amcache_copy_error_token(GetLastError());
            break;
        }
        if (read_bytes == 0)
            break;
        total += read_bytes;
        if (total > kAmcacheMaxBytes) {
            ok = false;
            token = "hive_oversized";
            break;
        }
        DWORD written = 0;
        if (!WriteFile(dst.get(), buf.data(), read_bytes, &written, nullptr)) {
            ok = false;
            token = amcache_copy_error_token(GetLastError());
            break;
        }
        if (written != read_bytes) {
            ok = false;
            token = "hive_short_write";
            break;
        }
    }
    if (!ok)
        DeleteFileW(dest);
    return token; // empty on success
}

// ── Prefetch ─────────────────────────────────────────────────────────────

constexpr wchar_t kPrefetchGlob[] = L"C:\\Windows\\Prefetch\\*.pf";
constexpr wchar_t kPrefetchDir[] = L"C:\\Windows\\Prefetch\\";
constexpr size_t kPrefetchMaxFiles = 2048;
constexpr uint64_t kPrefetchPerFileMaxBytes = 8ull * 1024 * 1024;   // 8 MiB
constexpr uint64_t kPrefetchTotalMaxBytes = 256ull * 1024 * 1024;   // 256 MiB

// A1 probe evidence: RtlGetCompressionWorkSpaceSize reported format
// COMPRESSION_FORMAT_XPRESS_HUFF = 4 in every run. Defined locally rather
// than pulled from a Windows SDK header (whose availability under the
// NTDDI_VERSION guard this file does not want to depend on) since only the
// numeric value is needed.
constexpr USHORT kCompressionFormatXpressHuff = 4;

using RtlGetCompressionWorkSpaceSizeFn = NTSTATUS(NTAPI*)(USHORT, PULONG, PULONG);
using RtlDecompressBufferExFn = NTSTATUS(NTAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG,
                                                 PVOID);

// Resolved ONCE via GetProcAddress(GetModuleHandleW(L"ntdll.dll"), ...) --
// this package's spec, "no #ifdef around the symbol": absence is a runtime
// outcome (ntdll_symbol_missing), never a compile-time exclusion of this
// leg. Magic-static idiom mirrors confined_fs_win.cpp's
// resolve_ntcreatefile/resolve_rtl_ntstatus_to_doserror.
RtlGetCompressionWorkSpaceSizeFn resolve_workspace_size_fn() {
    static const RtlGetCompressionWorkSpaceSizeFn resolved = []() -> RtlGetCompressionWorkSpaceSizeFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return nullptr;
        return reinterpret_cast<RtlGetCompressionWorkSpaceSizeFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize")));
    }();
    return resolved;
}

RtlDecompressBufferExFn resolve_decompress_fn() {
    static const RtlDecompressBufferExFn resolved = []() -> RtlDecompressBufferExFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return nullptr;
        return reinterpret_cast<RtlDecompressBufferExFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlDecompressBufferEx")));
    }();
    return resolved;
}

/// Decompresses a MAM-compressed `.pf` payload into `out`. Returns an empty
/// token on success; a non-empty token (ntdll_symbol_missing, a parser
/// token from mam_uncompressed_size, or ntstatus_<hex>) on failure.
std::string decompress_mam(std::span<const uint8_t> raw, std::vector<uint8_t>& out) {
    const auto workspace_size_fn = resolve_workspace_size_fn();
    const auto decompress_fn = resolve_decompress_fn();
    if (!workspace_size_fn || !decompress_fn)
        return "ntdll_symbol_missing";

    auto usize = mam_uncompressed_size(raw); // parsers.hpp: bounds-checks against kMamMaxUncompressedSize
    if (!usize)
        return usize.error().token;

    ULONG workspace_bytes = 0, fragment_bytes = 0;
    const NTSTATUS ws_status =
        workspace_size_fn(kCompressionFormatXpressHuff, &workspace_bytes, &fragment_bytes);
    if (ws_status != 0)
        return ntstatus_token(ws_status);

    std::vector<uint8_t> workspace(workspace_bytes > 0 ? workspace_bytes : 1);
    out.assign(*usize, 0);

    // MAM header is 8 bytes (4-byte "MAM\x04" magic + 4-byte uncompressed
    // size, both validated by mam_uncompressed_size above) -- the compressed
    // payload starts immediately after it.
    auto* compressed = const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(raw.data() + 8));
    const ULONG compressed_bytes = static_cast<ULONG>(raw.size() - 8);

    ULONG final_size = 0;
    const NTSTATUS dec_status =
        decompress_fn(kCompressionFormatXpressHuff, out.empty() ? nullptr : out.data(),
                     static_cast<ULONG>(out.size()), compressed, compressed_bytes, &final_size,
                     workspace.data());
    if (dec_status != 0)
        return ntstatus_token(dec_status);

    out.resize(final_size);
    return {};
}

} // namespace

// ═══════════════════════════════════════════════════════════ ShimCache ════

int collect_shimcache(yuzu::CommandContext& ctx) {
    try {
        yuzu::win::RegKey key;
        const LSTATUS open_rc =
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, kShimCacheSubkey, 0, KEY_READ, key.put());
        if (open_rc != ERROR_SUCCESS)
            return emit_constrained(ctx, "reg_" + std::to_string(open_rc));

        std::vector<uint8_t> blob;
        LSTATUS blob_rc = ERROR_SUCCESS;
        switch (read_shimcache_blob(key.get(), blob, blob_rc)) {
        case ShimBlobStatus::oversized:
            return emit_constrained(ctx, "oversized");
        case ShimBlobStatus::changed_during_read:
            return emit_constrained(ctx, "reg_changed_during_read");
        case ShimBlobStatus::not_found:
            return emit_constrained(ctx, "reg_" + std::to_string(blob_rc));
        case ShimBlobStatus::ok:
            break;
        }

        auto parsed = parse_shimcache(blob);
        if (!parsed) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  parsed.error().token);
            ctx.write_output("constrained|" + parsed.error().token +
                             "|offset=" + std::to_string(parsed.error().offset));
            return 1;
        }
        if (parsed->rows.empty())
            return emit_constrained(ctx, "shimcache_empty");

        for (const auto& row : parsed->rows)
            ctx.write_output(format_shimcache_row(row.path, row.last_modified_epoch_ms, row.data_size));

        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        return 0;
    } catch (...) {
        return emit_constrained(ctx, "internal_error");
    }
}

// ═══════════════════════════════════════════════════════════════ Amcache ══

int collect_amcache(yuzu::CommandContext& ctx) {
    try {
        WIN32_FILE_ATTRIBUTE_DATA attr{};
        if (!GetFileAttributesExW(kAmcacheSourceHve, GetFileExInfoStandard, &attr))
            return emit_constrained(ctx, "hive_missing");
        const uint64_t src_bytes =
            (static_cast<uint64_t>(attr.nFileSizeHigh) << 32) | attr.nFileSizeLow;
        if (src_bytes > kAmcacheMaxBytes)
            return emit_constrained(ctx, "hive_oversized");

        CreateDirectoryW(L"C:\\ProgramData\\yuzu\\agent", nullptr); // best-effort; may pre-exist

        // Owner-only, inheritable DACL (same D:P(A;;GA;;;OW) idiom as
        // temp_file.cpp's make_owner_only_sa, +OICI so it propagates to the
        // .LOG1/.LOG2 side files the registry engine creates loading the
        // hive) -- this dir holds the RAW Amcache.hve copy, not just
        // paths/hashes, and must not inherit ProgramData's Users-readable
        // default.
        PSECURITY_DESCRIPTOR amcache_sd = nullptr;
        SECURITY_ATTRIBUTES amcache_sa{sizeof(amcache_sa), nullptr, FALSE};
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;OICI;GA;;;OW)", SDDL_REVISION_1, &amcache_sd, nullptr))
            amcache_sa.lpSecurityDescriptor = amcache_sd;
        CreateDirectoryW(amcache_dest_dir().c_str(), amcache_sd ? &amcache_sa : nullptr);
        if (amcache_sd)
            LocalFree(amcache_sd);

        const std::wstring dest_hve = amcache_temp_path();

        // ENTIRE privilege-bearing sequence -- PrivilegeScope construction
        // (fallback path only), the copy, RegLoadAppKeyW, enumeration, and
        // RegCloseKey -- runs under this ONE lock, exactly as with_user_hive
        // (win_profiles.hpp:479-535) holds it for its whole offline arm. See
        // the file banner for the hold-time bound.
        const std::lock_guard<std::mutex> offline_lock(yuzu::agent::offline_hive_mutex());

        TempHiveCleanup cleanup(ctx);
        // Registered before the first CopyFileW attempt (not only on its
        // success path) so a possibly-partial file left behind by a failed
        // or interrupted copy still gets cleaned up (SYN-06) -- a one-line,
        // no-downside change regardless of whether CopyFileW itself can
        // leave a partial file on every failure mode.
        cleanup.add(dest_hve);

        if (!CopyFileW(kAmcacheSourceHve, dest_hve.c_str(), FALSE)) {
            const DWORD copy_err = GetLastError();
            if (copy_err != ERROR_SHARING_VIOLATION)
                return emit_constrained(ctx, amcache_copy_error_token(copy_err));

            const std::string fallback_token = copy_amcache_via_backup_semantics(dest_hve.c_str());
            if (!fallback_token.empty())
                return emit_constrained(ctx, fallback_token);
        }

        // Re-check the ACTUAL copied bytes against kAmcacheMaxBytes here,
        // under the lock, instead of trusting only the pre-lock src_bytes
        // stat above: that stat ran BEFORE this action waited to acquire
        // offline_hive_mutex, so the source hive can grow past the cap
        // during the wait, and plain CopyFileW -- unlike the backup-
        // semantics fallback's own streaming total-vs-cap check -- enforces
        // no byte limit of its own; it would copy an oversized file
        // straight through.
        {
            WIN32_FILE_ATTRIBUTE_DATA dest_attr{};
            if (GetFileAttributesExW(dest_hve.c_str(), GetFileExInfoStandard, &dest_attr)) {
                const uint64_t dest_bytes =
                    (static_cast<uint64_t>(dest_attr.nFileSizeHigh) << 32) | dest_attr.nFileSizeLow;
                if (dest_bytes > kAmcacheMaxBytes)
                    return emit_constrained(ctx, "hive_oversized");
            }
        }

        // .LOG1/.LOG2 -- best-effort only, plain copy, never the privilege
        // fallback: RegLoadAppKeyW's read of the main .hve is this leg's only
        // hard requirement (this package's spec: "+.LOG1/.LOG2 when present").
        //
        // Cleanup is registered BEFORE the copy attempt, same as dest_hve
        // above (SYN-06) -- an interrupted sidecar copy can leave a partial
        // .LOG1/.LOG2 temp file behind just as easily as the main hive, and
        // that file must not leak just because it wasn't the copy that
        // "succeeded".
        for (const wchar_t* ext : {L".LOG1", L".LOG2"}) {
            const std::wstring src_log = std::wstring{kAmcacheSourceHve} + ext;
            const std::wstring dst_log = dest_hve + ext;
            cleanup.add(dst_log);
            if (CopyFileW(src_log.c_str(), dst_log.c_str(), FALSE)) {
                // Sidecars have no size check of their own otherwise --
                // bound them by the same cap so a huge .LOG1/.LOG2 can't
                // defeat the advertised copy bound. Best-effort: drop the
                // oversized sidecar rather than failing the action over a
                // non-hard-requirement file.
                WIN32_FILE_ATTRIBUTE_DATA log_attr{};
                if (GetFileAttributesExW(dst_log.c_str(), GetFileExInfoStandard, &log_attr)) {
                    const uint64_t log_bytes = (static_cast<uint64_t>(log_attr.nFileSizeHigh) << 32) |
                                                log_attr.nFileSizeLow;
                    if (log_bytes > kAmcacheMaxBytes)
                        DeleteFileW(dst_log.c_str());
                }
            }
        }

        HKEY loaded_raw = nullptr;
        const LSTATUS load_rc =
            RegLoadAppKeyW(dest_hve.c_str(), &loaded_raw, KEY_READ, REG_PROCESS_APPKEY, 0);
        if (load_rc != ERROR_SUCCESS)
            return emit_constrained(ctx, "regload_" + std::to_string(load_rc));
        yuzu::win::RegKey loaded_key(loaded_raw);

        yuzu::win::RegKey root_key;
        if (RegOpenKeyExW(loaded_key.get(), L"Root\\InventoryApplicationFile", 0, KEY_READ,
                          root_key.put()) != ERROR_SUCCESS)
            return emit_constrained(ctx, "amcache_root_missing");

        std::vector<std::pair<std::string, std::map<std::string, std::string>>> subkeys;
        yuzu::shared::ConstraintAccumulator acc;
        constexpr DWORD kNameBufLen = 256;
        wchar_t name_buf[kNameBufLen];
        DWORD idx = 0;
        for (;;) {
            // Capped on attempted entries (idx), not on subkeys.size() --
            // a denied/vanished RegOpenKeyExW below still advances idx via
            // RegEnumKeyExW without ever growing subkeys, so gating on the
            // successful-open count let a subkey run with many denials
            // enumerate/open far more than kAmcacheMaxSubkeys times while
            // holding the shared offline-hive lock.
            if (idx >= kAmcacheMaxSubkeys) {
                acc.add_failure("subkey_cap");
                acc.mark_incomplete();
                break;
            }
            DWORD name_len = kNameBufLen;
            const LSTATUS enum_rc =
                RegEnumKeyExW(root_key.get(), idx, name_buf, &name_len, nullptr, nullptr, nullptr,
                             nullptr);
            if (enum_rc != ERROR_SUCCESS) {
                if (enum_rc != ERROR_NO_MORE_ITEMS) { // a genuine mid-walk failure, not exhaustion
                    acc.add_failure("enum_" + std::to_string(enum_rc));
                    acc.mark_incomplete();
                }
                break;
            }
            ++idx;

            std::string subkey_name = yuzu::win::from_wide(name_buf, static_cast<int>(name_len));
            yuzu::win::RegKey subkey;
            if (RegOpenKeyExW(root_key.get(), name_buf, 0, KEY_READ, subkey.put()) !=
                ERROR_SUCCESS) {
                // vanished/denied mid-walk -- real loss, not silent
                acc.add_failure("subkey_open_failed");
                acc.mark_incomplete();
                continue;
            }

            auto value_names = yuzu::win::enumerate_value_names(subkey.get());
            if (!value_names.complete) {
                acc.add_failure("value_enum_incomplete");
                acc.mark_incomplete();
            }

            std::map<std::string, std::string> values;
            for (const auto& vname : value_names.names) {
                std::string out_value, out_type;
                if (yuzu::win::read_reg_value(subkey.get(), vname, out_value, out_type) ==
                    yuzu::win::ReadValueStatus::ok) {
                    values.emplace(vname, std::move(out_value));
                } else {
                    // win_profiles.hpp's ReadValueStatus exists specifically
                    // so a caller can tell "value read failed" apart from
                    // "value absent" -- collapsing every non-ok status
                    // (denied, oversized, malformed, changed-during-read)
                    // into silent omission throws that signal away and
                    // reports a row with a missing field as if the read had
                    // been complete (SYN-02).
                    acc.add_failure("value_read_failed");
                    acc.mark_incomplete();
                }
            }
            subkeys.emplace_back(std::move(subkey_name), std::move(values));
        }

        const AmCacheResult parsed = parse_amcache_inventory_application_file(subkeys);
        if (parsed.rows.empty())
            // Compose with acc.reason_with() rather than the bare token --
            // an empty result after e.g. subkey_cap/enum_*/subkey_open_failed
            // fired must still surface those accumulated reasons, not
            // silently discard them behind "amcache_empty".
            return emit_constrained(ctx, acc.reason_with("amcache_empty"));

        for (const auto& row : parsed.rows) {
            ctx.write_output(format_amcache_row(row.lower_case_long_path, row.sha1, row.size,
                                                row.link_date, row.publisher, row.binary_type,
                                                row.product_name, row.product_version));
        }

        // AmCacheResult::malformed_fields is computed but had no consumer
        // anywhere in the tree (SYN-01) -- its own doc comment promises it
        // is "never silently dropped". Surface it as its own note row
        // (same shape as this file's temp_cleanup_failed note) rather than
        // folding it into truncated/subkey_cap, which already means a
        // distinct thing (registry enumeration was incomplete).
        if (parsed.malformed_fields > 0)
            ctx.write_output("note|malformed_fileid_count=" +
                             std::to_string(parsed.malformed_fields));

        ctx.set_result_status(acc.incomplete() ? YUZU_RESULT_STATUS_CONSTRAINED
                                               : YUZU_RESULT_STATUS_OK,
                              acc.incomplete() ? YUZU_RESULT_COMPLETENESS_PARTIAL
                                               : YUZU_RESULT_COMPLETENESS_FULL,
                              acc.reason());
        return acc.incomplete() ? 1 : 0;
        // `cleanup` (TempHiveCleanup), `root_key` and `loaded_key` destruct
        // here in reverse declaration order on every return path above --
        // RegCloseKey (root_key, then loaded_key) always runs before
        // DeleteFileW (cleanup), matching this package's "RegCloseKey;
        // DeleteFileW the copies in a scope guard" ordering.
    } catch (...) {
        return emit_constrained(ctx, "internal_error");
    }
}

// ═══════════════════════════════════════════════════════════════ Prefetch ═

int collect_prefetch(yuzu::CommandContext& ctx) {
    try {
        WIN32_FIND_DATAW find_data{};
        ScopedFindHandle find(FindFirstFileW(kPrefetchGlob, &find_data));
        if (!find) {
            const DWORD err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                return emit_constrained(ctx, "prefetch_disabled");
            return emit_constrained(ctx, "prefetch_enum_" + std::to_string(err));
        }

        size_t files_seen = 0;
        size_t rows_emitted = 0;
        uint64_t total_bytes = 0;
        // file_cap / byte_cap / a mid-walk enumeration fault -> acc.mark_incomplete()
        // (the enumeration was TRUNCATED); a single .pf skipped with a
        // prefetch_error| row -> acc.add_failure() only (enumeration completed).
        yuzu::shared::ConstraintAccumulator acc;

        do {
            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                continue;

            if (files_seen >= kPrefetchMaxFiles) {
                acc.add_failure("file_cap");
                acc.mark_incomplete();
                break;
            }
            ++files_seen;

            const std::string fname =
                yuzu::util::safe_output_field(yuzu::win::from_wide(find_data.cFileName));
            const uint64_t file_bytes =
                (static_cast<uint64_t>(find_data.nFileSizeHigh) << 32) | find_data.nFileSizeLow;

            if (file_bytes > kPrefetchPerFileMaxBytes) {
                ctx.write_output("prefetch_error|" + fname + "|file_oversized");
                acc.add_failure("file_oversized");
                continue;
            }
            if (total_bytes + file_bytes > kPrefetchTotalMaxBytes) {
                acc.add_failure("byte_cap");
                acc.mark_incomplete();
                break;
            }

            const std::wstring full_path = std::wstring{kPrefetchDir} + find_data.cFileName;
            ScopedHandle fh(CreateFileW(full_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (!fh) {
                ctx.write_output("prefetch_error|" + fname + "|read_failed");
                acc.add_failure("read_failed");
                continue;
            }
            std::vector<uint8_t> bytes(static_cast<size_t>(file_bytes));
            DWORD read_bytes = 0;
            const bool read_ok =
                bytes.empty() || (ReadFile(fh.get(), bytes.data(), static_cast<DWORD>(bytes.size()),
                                          &read_bytes, nullptr) &&
                                 read_bytes == bytes.size());
            if (!read_ok) {
                ctx.write_output("prefetch_error|" + fname + "|read_failed");
                acc.add_failure("read_failed");
                continue;
            }
            total_bytes += bytes.size();

            std::vector<uint8_t> decompressed;
            std::span<const uint8_t> payload = bytes;
            if (is_mam_compressed(payload)) {
                const std::string dec_token = decompress_mam(payload, decompressed);
                if (!dec_token.empty()) {
                    ctx.write_output("prefetch_error|" + fname + "|" + dec_token);
                    acc.add_failure(dec_token);
                    continue;
                }
                payload = decompressed;
            }

            auto parsed = parse_prefetch(payload);
            if (!parsed) {
                ctx.write_output("prefetch_error|" + fname + "|" + parsed.error().token);
                acc.add_failure(parsed.error().token);
                continue;
            }

            ctx.write_output(format_prefetch_row(parsed->exe_name, parsed->hash_hex,
                                                 parsed->version, parsed->run_count,
                                                 parsed->last_runs_epoch_ms, parsed->volume_count,
                                                 parsed->file_ref_count));
            ++rows_emitted;
        } while (FindNextFileW(find.get(), &find_data));

        // FindNextFileW returning false is ambiguous on its own --
        // ERROR_NO_MORE_FILES is the normal, expected end of enumeration,
        // but any other GetLastError() means a genuine I/O fault ended the
        // walk early, indistinguishable from clean exhaustion without this
        // check (SYN-03). Skip it when the loop instead exited via one of
        // the caps above (acc.incomplete() already set) -- that path breaks
        // out of the loop body before FindNextFileW runs again, so
        // GetLastError() would reflect a stale prior call, not the reason
        // the walk stopped.
        if (!acc.incomplete()) {
            const DWORD find_err = GetLastError();
            if (find_err != ERROR_NO_MORE_FILES) {
                acc.add_failure("prefetch_enum_" + std::to_string(find_err));
                acc.mark_incomplete();
            }
        }

        if (files_seen == 0 && !acc.any_failure())
            return emit_constrained(ctx, "prefetch_disabled");

        if (acc.incomplete())
            ctx.write_output("constrained|" + acc.reason());

        // Exit code agrees with the typed status (legs.hpp contract: 0 only on OK):
        //   - a cap fired -> the enumeration was TRUNCATED -> CONSTRAINED/PARTIAL, rc 1;
        //   - only per-file errors -> the enumeration COMPLETED and every skipped file
        //     is already on the stream as a prefetch_error| row -> OK/PARTIAL, rc 0
        //     (the-rig 2026-09-07: one truncated WERFAULT .pf must not fail 302 good rows);
        //   - neither -> OK/FULL, rc 0.
        const YuzuResultStatus status =
            acc.incomplete() ? YUZU_RESULT_STATUS_CONSTRAINED : YUZU_RESULT_STATUS_OK;
        const YuzuResultCompleteness completeness =
            acc.any_failure() ? YUZU_RESULT_COMPLETENESS_PARTIAL : YUZU_RESULT_COMPLETENESS_FULL;
        ctx.set_result_status(status, completeness, acc.reason());
        (void)rows_emitted; // kept for readability at call sites reading this function
        return acc.incomplete() ? 1 : 0;
    } catch (...) {
        return emit_constrained(ctx, "internal_error");
    }
}

} // namespace yuzu::execution_artifacts

#endif // defined(_WIN32)
