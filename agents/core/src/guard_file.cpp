/**
 * guard_file.cpp — see guard_file.hpp.
 *
 * Windows: one watch thread holds a wait set of {dir-change, ancestor-change,
 * stop} and runs reconcile() on every wakeup. reconcile() re-resolves from
 * scratch — if the parent directory exists, arm ReadDirectoryChangesW on it and
 * re-check the target's presence; else walk up to the nearest existing ancestor
 * and watch it for the parent's (re)creation. Arming happens BEFORE the presence
 * check so a change in the arm→check gap re-fires. This makes the guard resilient
 * (design §24): it survives the parent dir — and its whole ancestor chain — being
 * deleted and recreated, and keeps detecting until stop().
 *
 * Only changes to OUR filename (parsed from the FILE_NOTIFY_INFORMATION records)
 * trigger a reconcile, so a busy sibling-heavy directory does not wake us
 * needlessly (network-kindness / NFR). A buffer overflow (bytesReturned == 0)
 * reconciles unconditionally — we can't know what changed.
 *
 * Detection-only: a FileGuard never writes (file-content remediation needs
 * Content Distribution; deferred). Proto-free + windows.h-free header. On
 * non-Windows the guard is a no-op (start() returns false).
 */

#include <yuzu/agent/guard_file.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <filesystem>
#include <optional>
#include <system_error>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstddef>
#include <string>

namespace yuzu::agent {
namespace {

std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) return {};
    std::wstring w(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// Case-insensitive wide compare (Windows filenames are case-insensitive). Ordinal
// (not locale) — a filename match is a byte/codepoint identity check, not a
// linguistic one.
bool iequals_w(std::wstring_view a, std::wstring_view b) {
    return a.size() == b.size() &&
           CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(),
                                static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}

} // namespace

FileGuard::FileGuard(Config cfg, GuardSink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}

FileGuard::~FileGuard() { stop(); }

bool FileGuard::start() {
    if (cfg_.path.empty())
        return false;

    // Canonicalise so the parent-dir watch tracks the real location: resolves
    // `..`, mixed separators, and symlinks/junctions in the EXISTING prefix.
    // weakly_canonical (not canonical) so a not-yet-existing target is still
    // accepted — file-exists legitimately watches a path that may not exist yet
    // (expect absent), and we want to detect its creation.
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(fs::path(cfg_.path), ec);
    if (!ec && !canon.empty())
        cfg_.path = canon.string();

    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr); // manual-reset stop
    if (!stop_event_)
        return false;
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
    return true;
}

void FileGuard::stop() {
    stop_.store(true, std::memory_order_release);
    if (stop_event_)
        SetEvent(static_cast<HANDLE>(stop_event_));
    if (thread_.joinable())
        thread_.join();
    if (stop_event_) {
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
    }
}

void FileGuard::run() {
    namespace fs = std::filesystem;
    const fs::path target(cfg_.path);
    const fs::path parent = target.parent_path();
    const std::wstring fname = target.filename().wstring();

    // ReadDirectoryChangesW notification buffer (DWORD-aligned). 32 KiB holds many
    // records; on overflow we reconcile unconditionally, so the size is a perf knob
    // not a correctness one.
    alignas(DWORD) std::byte notify_buf[32 * 1024];

    HANDLE dir_event = CreateEventW(nullptr, FALSE, FALSE, nullptr); // auto-reset OVERLAPPED hEvent
    OVERLAPPED ov{};
    ov.hEvent = dir_event;
    HANDLE h_dir = INVALID_HANDLE_VALUE;       // parent dir, open for ReadDirectoryChangesW
    HANDLE ancestor_event = nullptr;            // FindFirstChangeNotification (waitable)
    bool read_pending = false;

    // Collapse-with-count debounce (shared convention with RegistryGuard, H3/#1209).
    std::optional<std::chrono::steady_clock::time_point> last_emit;
    std::uint64_t suppressed = 0;

    auto close_dir = [&] {
        if (h_dir != INVALID_HANDLE_VALUE) {
            CancelIo(h_dir);
            CloseHandle(h_dir);
            h_dir = INVALID_HANDLE_VALUE;
        }
        read_pending = false;
    };
    auto close_ancestor = [&] {
        if (ancestor_event) {
            FindCloseChangeNotification(ancestor_event);
            ancestor_event = nullptr;
        }
    };

    // (Re)issue ReadDirectoryChangesW on the already-open parent handle.
    auto arm_dir_read = [&]() -> bool {
        constexpr DWORD kFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                  FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                                  FILE_NOTIFY_CHANGE_CREATION;
        read_pending = ReadDirectoryChangesW(h_dir, notify_buf, sizeof(notify_buf), FALSE, kFilter,
                                             nullptr, &ov, nullptr) != 0;
        return read_pending;
    };

    auto emit = [&](bool present) {
        const bool drift = (present != cfg_.expect_present);
        if (!drift)
            return;
        GuardDrift d;
        d.guard_type = "file";
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.detected_value = present ? "<present>" : "<absent>";
        d.expected_value = cfg_.expect_present ? "<present>" : "<absent>";
        const auto now = std::chrono::steady_clock::now();
        if (last_emit && (now - *last_emit) < std::chrono::milliseconds(cfg_.event_debounce_ms)) {
            ++suppressed; // fold into the next post-window emission
            return;
        }
        d.collapsed_count = suppressed;
        suppressed = 0;
        last_emit = now;
        spdlog::info("Guardian FileGuard[{}]: {} (expected {}) for {}", cfg_.rule_id,
                     present ? "present" : "absent", cfg_.expect_present ? "present" : "absent",
                     cfg_.path);
        if (sink_)
            sink_(d);
    };

    // Re-resolve from scratch: arm the parent-dir watch if the parent exists, else
    // arm the nearest-ancestor watch; then re-check the target and emit.
    auto reconcile = [&]() {
        close_dir();
        close_ancestor();
        std::error_code ec;
        const bool parent_ok = !parent.empty() && fs::is_directory(parent, ec);
        if (parent_ok) {
            h_dir = CreateFileW(parent.wstring().c_str(), FILE_LIST_DIRECTORY,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                nullptr);
            if (h_dir != INVALID_HANDLE_VALUE && !arm_dir_read())
                close_dir(); // open succeeded but the read arm failed → treat as absent
        }
        if (h_dir == INVALID_HANDLE_VALUE) {
            // Parent absent (or open failed): watch the nearest existing ancestor for
            // the parent's (re)creation. Subtree watch so a whole-chain recreate fires.
            fs::path anc = parent;
            std::error_code ec2;
            while (!anc.empty() && !fs::is_directory(anc, ec2))
                anc = anc.parent_path();
            if (!anc.empty())
                ancestor_event = FindFirstChangeNotificationW(
                    anc.wstring().c_str(), TRUE,
                    FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_FILE_NAME);
        }
        std::error_code ec3;
        emit(fs::exists(target, ec3));
    };

    // True iff the completed read mentions our target filename (or overflowed).
    auto change_is_ours = [&](DWORD bytes) -> bool {
        if (bytes == 0)
            return true; // buffer overflow — can't tell, reconcile
        auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(notify_buf);
        for (;;) {
            const std::wstring_view name(info->FileName, info->FileNameLength / sizeof(WCHAR));
            if (iequals_w(name, fname))
                return true;
            if (info->NextEntryOffset == 0)
                break;
            info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(
                reinterpret_cast<const std::byte*>(info) + info->NextEntryOffset);
        }
        return false;
    };

    spdlog::info("Guardian FileGuard[{}]: watching {} (expect {}) [resilient]", cfg_.rule_id,
                 cfg_.path, cfg_.expect_present ? "present" : "absent");
    reconcile(); // initial arm + compare

    while (!stop_.load(std::memory_order_acquire)) {
        HANDLE handles[3];
        DWORD n = 0;
        const DWORD idx_dir = (h_dir != INVALID_HANDLE_VALUE && read_pending) ? n : 0xFFFFFFFF;
        if (idx_dir != 0xFFFFFFFF)
            handles[n++] = dir_event;
        const DWORD idx_anc = ancestor_event ? n : 0xFFFFFFFF;
        if (idx_anc != 0xFFFFFFFF)
            handles[n++] = ancestor_event;
        const DWORD idx_stop = n;
        handles[n++] = static_cast<HANDLE>(stop_event_);

        const DWORD r = WaitForMultipleObjects(n, handles, FALSE, INFINITE);
        if (r == WAIT_OBJECT_0 + idx_stop)
            break;
        if (idx_dir != 0xFFFFFFFF && r == WAIT_OBJECT_0 + idx_dir) {
            DWORD bytes = 0;
            GetOverlappedResult(h_dir, &ov, &bytes, FALSE);
            read_pending = false;
            if (change_is_ours(bytes))
                reconcile(); // re-opens + re-arms + re-checks
            else if (!arm_dir_read())
                reconcile(); // re-arm failed → rebuild from scratch
        } else if (idx_anc != 0xFFFFFFFF && r == WAIT_OBJECT_0 + idx_anc) {
            reconcile();
        } else {
            break; // WAIT_FAILED / WAIT_ABANDONED — unrecoverable
        }
    }

    close_dir();
    close_ancestor();
    CloseHandle(dir_event);
}

} // namespace yuzu::agent

#else // !_WIN32

namespace yuzu::agent {

FileGuard::FileGuard(Config cfg, GuardSink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}
FileGuard::~FileGuard() = default;
bool FileGuard::start() { return false; } // file-change Spark is Windows-only for the MVP
void FileGuard::stop() {}
void FileGuard::run() {}

} // namespace yuzu::agent

#endif // _WIN32
