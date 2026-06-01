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

#include <yuzu/agent/plugin_loader.hpp> // sha256_file (bounded)

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
    const bool hash_mode = (cfg_.assertion == Assertion::HashEquals);

    // ReadDirectoryChangesW notification buffer (DWORD-aligned). 32 KiB holds many
    // records; on overflow we reconcile unconditionally, so the size is a perf knob
    // not a correctness one.
    alignas(DWORD) std::byte notify_buf[32 * 1024];

    HANDLE dir_event = CreateEventW(nullptr, FALSE, FALSE, nullptr); // auto-reset OVERLAPPED hEvent
    OVERLAPPED ov{};
    ov.hEvent = dir_event;
    HANDLE h_dir = INVALID_HANDLE_VALUE; // parent dir, open for ReadDirectoryChangesW
    HANDLE ancestor_event = nullptr;     // FindFirstChangeNotification (waitable)
    bool read_pending = false;

    // Collapse-with-count debounce (shared convention with RegistryGuard, H3/#1209).
    std::optional<std::chrono::steady_clock::time_point> last_emit;
    std::uint64_t suppressed = 0;

    // file-hash-equals state.
    std::string baseline;      // captured-on-arm hash when expected_hash is empty
    bool baseline_set = false;
    bool hash_pending = false; // a change is settling before we (re)hash

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
        if (h_dir == INVALID_HANDLE_VALUE)
            return false;
        constexpr DWORD kFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                  FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                                  FILE_NOTIFY_CHANGE_CREATION;
        read_pending = ReadDirectoryChangesW(h_dir, notify_buf, sizeof(notify_buf), FALSE, kFilter,
                                             nullptr, &ov, nullptr) != 0;
        return read_pending;
    };

    auto report = [&](const std::string& detected, const std::string& expected) {
        const auto now = std::chrono::steady_clock::now();
        if (last_emit && (now - *last_emit) < std::chrono::milliseconds(cfg_.event_debounce_ms)) {
            ++suppressed; // fold into the next post-window emission
            return;
        }
        GuardDrift d;
        d.guard_type = "file";
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.detected_value = detected;
        d.expected_value = expected;
        d.collapsed_count = suppressed;
        suppressed = 0;
        last_emit = now;
        if (sink_)
            sink_(d);
    };

    // file-exists: drift when presence != expected.
    auto eval_exists = [&] {
        std::error_code ec;
        const bool present = fs::exists(target, ec);
        if (present != cfg_.expect_present) {
            spdlog::info("Guardian FileGuard[{}]: {} (expected {}) for {}", cfg_.rule_id,
                         present ? "present" : "absent", cfg_.expect_present ? "present" : "absent",
                         cfg_.path);
            report(present ? "<present>" : "<absent>",
                   cfg_.expect_present ? "<present>" : "<absent>");
        }
    };

    // file-hash-equals: drift when content (bounded SHA-256) differs from the
    // baseline / expected hash. Reads the PATH (independent of the dir handle) so it
    // is correct regardless of watch state. Fail-loud on absent / oversize /
    // unreadable — never a silent "compliant" (G11/N3).
    auto eval_hash = [&] {
        std::error_code ec;
        const std::string expected_disp =
            cfg_.expected_hash.empty() ? (baseline_set ? baseline : std::string{"<baseline>"})
                                       : cfg_.expected_hash;
        if (!fs::exists(target, ec)) {
            report("<absent>", expected_disp);
            return;
        }
        const auto sz = fs::file_size(target, ec);
        if (ec) {
            report("<unreadable>", expected_disp);
            return;
        }
        if (sz > cfg_.max_hash_bytes) {
            // Too large to verify within the DoS cap — report rather than skip, so
            // the operator sees "can't verify", not a false compliant.
            report("<oversize>", expected_disp);
            return;
        }
        // Hash on each settled change — once per quiescence window, so cheap, and it
        // puts the actual digest in every drift report. Bounded by max_hash_bytes (a
        // TOCTOU-grow / DoS defence). NB: a size-delta pre-filter to skip hashing was
        // considered and dropped — the per-event cost is negligible and unconditional
        // hashing keeps the forensic digest (a size-only signal would lose it).
        const std::string cur =
            sha256_file(target, static_cast<std::size_t>(cfg_.max_hash_bytes));
        if (cur.empty()) {
            // Grew past the cap mid-read (TOCTOU) or read error → can't verify.
            report("<unreadable>", expected_disp);
            return;
        }
        if (cfg_.expected_hash.empty() && !baseline_set) {
            baseline = cur; // baseline-on-arm: first present read establishes the good state
            baseline_set = true;
            spdlog::info("Guardian FileGuard[{}]: baselined {} = {}", cfg_.rule_id, cfg_.path, cur);
            return; // no drift — we just captured the baseline
        }
        const std::string& effective = cfg_.expected_hash.empty() ? baseline : cfg_.expected_hash;
        if (cur != effective) {
            spdlog::info("Guardian FileGuard[{}]: content drift on {} ({} != {})", cfg_.rule_id,
                         cfg_.path, cur, effective);
            report(cur, effective);
        }
    };

    // Re-resolve the watch from scratch (no eval): arm the parent-dir watch if the
    // parent exists, else the nearest-ancestor watch for its (re)creation.
    auto arm_watch = [&] {
        close_dir();
        close_ancestor();
        std::error_code ec;
        if (!parent.empty() && fs::is_directory(parent, ec)) {
            h_dir = CreateFileW(parent.wstring().c_str(), FILE_LIST_DIRECTORY,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                nullptr);
            if (h_dir != INVALID_HANDLE_VALUE && !arm_dir_read())
                close_dir();
        }
        if (h_dir == INVALID_HANDLE_VALUE) {
            fs::path anc = parent;
            std::error_code ec2;
            while (!anc.empty() && !fs::is_directory(anc, ec2))
                anc = anc.parent_path();
            if (!anc.empty())
                ancestor_event = FindFirstChangeNotificationW(
                    anc.wstring().c_str(), TRUE,
                    FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_FILE_NAME);
        }
    };

    auto eval_now = [&] {
        if (hash_mode)
            eval_hash();
        else
            eval_exists();
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

    spdlog::info("Guardian FileGuard[{}]: watching {} ({}) [resilient]", cfg_.rule_id, cfg_.path,
                 hash_mode ? "hash-equals"
                           : (cfg_.expect_present ? "expect present" : "expect absent"));
    arm_watch();
    eval_now(); // initial compare (hash: baseline-on-arm or compare to expected)

    while (!stop_.load(std::memory_order_acquire)) {
        HANDLE handles[3];
        DWORD n = 0;
        const DWORD idx_dir = read_pending ? n : 0xFFFFFFFF;
        if (idx_dir != 0xFFFFFFFF)
            handles[n++] = dir_event;
        const DWORD idx_anc = ancestor_event ? n : 0xFFFFFFFF;
        if (idx_anc != 0xFFFFFFFF)
            handles[n++] = ancestor_event;
        const DWORD idx_stop = n;
        handles[n++] = static_cast<HANDLE>(stop_event_);

        // Finite timeout only while a hash change is settling (writes are not atomic;
        // hash once the file quiesces). Otherwise block on OS events (no poll).
        const DWORD timeout =
            (hash_mode && hash_pending) ? static_cast<DWORD>(cfg_.settle_ms) : INFINITE;
        const DWORD r = WaitForMultipleObjects(n, handles, FALSE, timeout);
        if (r == WAIT_OBJECT_0 + idx_stop)
            break;
        if (r == WAIT_TIMEOUT) {
            // Settle window elapsed quietly → hash the now-quiesced content, then
            // re-resolve the watch (handles a parent deleted during the write).
            hash_pending = false;
            eval_hash();
            arm_watch();
        } else if (idx_dir != 0xFFFFFFFF && r == WAIT_OBJECT_0 + idx_dir) {
            DWORD bytes = 0;
            GetOverlappedResult(h_dir, &ov, &bytes, FALSE);
            read_pending = false;
            const bool ours = change_is_ours(bytes);
            if (!ours) {
                if (!arm_dir_read())
                    arm_watch(); // re-arm failed (dir gone) → rebuild
            } else if (hash_mode) {
                // Defer the (expensive, mid-write-prone) hash to the settle timeout;
                // just keep the read armed and (re)start the settle countdown.
                if (!arm_dir_read())
                    arm_watch();
                hash_pending = true;
            } else {
                arm_watch(); // existence: re-resolve + evaluate now
                eval_exists();
            }
        } else if (idx_anc != 0xFFFFFFFF && r == WAIT_OBJECT_0 + idx_anc) {
            arm_watch();
            if (hash_mode)
                hash_pending = true; // settle, then hash the (re)created file
            else
                eval_exists();
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
