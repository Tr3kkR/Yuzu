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
 * macOS: one watch thread waits on a condition variable fed by an FSEvents
 * stream (FsEventsWatchCore) on the parent directory — kernel-notified, NO
 * polling, same arm-before-check ordering. FSEvents subscriptions are
 * path-string based against the volume's global event stream, so the stream
 * keeps delivering after the parent is deleted and recreated — the Windows
 * nearest-ancestor machinery collapses into that one property (an ancestor
 * fallback watch exists only for the rare arm failure). WatchRoot flags a
 * moved/deleted parent as a reconcile.
 *
 * Only changes naming OUR filename (FILE_NOTIFY_INFORMATION records / FSEvents
 * event paths) trigger a reconcile, so a busy sibling-heavy directory does not
 * wake us needlessly (network-kindness / NFR). An unattributable notification
 * (Windows buffer overflow; FSEvents MustScanSubDirs/RootChanged/drops)
 * reconciles unconditionally — we can't know what changed.
 *
 * The evaluate/report state machine (presence + bounded-hash assertions,
 * drift debounce, Slice-B compliant edges) is platform-neutral and shared
 * (FileEvaluator below); only the watch plumbing differs per platform.
 *
 * Detection-only: a FileGuard never writes (file-content remediation needs
 * Content Distribution; deferred). Proto-free + OS-header-free public header.
 * On Linux the guard is still a no-op (start() returns false) — inotify is
 * later platform work.
 */

#include <yuzu/agent/guard_file.hpp>

#include <yuzu/agent/plugin_loader.hpp> // sha256_file (bounded)

#include <spdlog/spdlog.h>

#include <chrono>
#include <filesystem>
#include <optional>
#include <system_error>

#if defined(_WIN32) || defined(__APPLE__)

namespace yuzu::agent {
namespace {

// Canonicalise so the parent-dir watch tracks the real location: resolves
// `..`, mixed separators, and symlinks/junctions in the EXISTING prefix (on
// macOS notably /var → /private/var, /tmp → /private/tmp). weakly_canonical
// (not canonical) so a not-yet-existing target is still accepted — file-exists
// legitimately watches a path that may not exist yet (expect absent), and we
// want to detect its creation.
void canonicalize_target_path(FileGuard::Config& cfg) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(fs::path(cfg.path), ec);
    if (!ec && !canon.empty())
        cfg.path = canon.string();
}

// Platform-neutral evaluate/report state machine, shared by the Windows and
// macOS watch loops. Owns the drift debounce (collapse-with-count, shared
// convention with RegistryGuard, H3/#1209), the Slice-B compliant edge, and the
// file-exists / file-hash-equals assertions. Fail-loud on absent / oversize /
// unreadable in hash mode — never a silent "compliant" (G11/N3). Single-thread
// use only (the owning watch thread).
class FileEvaluator {
public:
    FileEvaluator(const FileGuard::Config& cfg, const GuardSink& sink, bool hash_mode)
        : cfg_(cfg), sink_(sink), hash_mode_(hash_mode), target_(cfg.path) {}

    void eval_now() {
        if (hash_mode_)
            eval_hash();
        else
            eval_exists();
    }

    /// Poll-originated evaluation (idle liveness recheck / degraded re-arm):
    /// identical repeat verdicts are suppressed so a steady drifted rule does
    /// not re-emit drift.detected on every poll tick forever (Gate-8 F1 — the
    /// event-originated paths keep their re-report semantics, which is the
    /// pre-existing cross-platform contract). Returns true when the eval
    /// TRANSITIONED compliance state — the caller can treat that as proof the
    /// event stream missed something and re-arm (Gate-8 F3).
    bool eval_poll() {
        poll_eval_ = true;
        transitioned_ = false;
        eval_now();
        poll_eval_ = false;
        return transitioned_;
    }

    // file-exists: drift when presence != expected.
    void eval_exists() {
        namespace fs = std::filesystem;
        std::error_code ec;
        const bool present = fs::exists(target_, ec);
        if (present != cfg_.expect_present) {
            spdlog::info("Guardian FileGuard[{}]: {} (expected {}) for {}", cfg_.rule_id,
                         present ? "present" : "absent", cfg_.expect_present ? "present" : "absent",
                         cfg_.path);
            report(present ? "<present>" : "<absent>",
                   cfg_.expect_present ? "<present>" : "<absent>");
        } else {
            report_compliant();
        }
    }

    // file-hash-equals: drift when content (bounded SHA-256) differs from the
    // baseline / expected hash. Reads the PATH (independent of any watch handle)
    // so it is correct regardless of watch state.
    void eval_hash() {
        namespace fs = std::filesystem;
        std::error_code ec;
        const std::string expected_disp =
            cfg_.expected_hash.empty() ? (baseline_set_ ? baseline_ : std::string{"<baseline>"})
                                       : cfg_.expected_hash;
        if (!fs::exists(target_, ec)) {
            report("<absent>", expected_disp);
            return;
        }
        const auto sz = fs::file_size(target_, ec);
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
            sha256_file(target_, static_cast<std::size_t>(cfg_.max_hash_bytes));
        if (cur.empty()) {
            // Grew past the cap mid-read (TOCTOU) or read error → can't verify.
            report("<unreadable>", expected_disp);
            return;
        }
        if (cfg_.expected_hash.empty() && !baseline_set_) {
            baseline_ = cur; // baseline-on-arm: first present read establishes the good state
            baseline_set_ = true;
            spdlog::info("Guardian FileGuard[{}]: baselined {} = {}", cfg_.rule_id, cfg_.path,
                         cur);
            report_compliant(); // armed at the known-good baseline → compliant edge
            return;             // no drift — we just captured the baseline
        }
        const std::string& effective = cfg_.expected_hash.empty() ? baseline_ : cfg_.expected_hash;
        if (cur != effective) {
            spdlog::info("Guardian FileGuard[{}]: content drift on {} ({} != {})", cfg_.rule_id,
                         cfg_.path, cur, effective);
            report(cur, effective);
        } else {
            report_compliant();
        }
    }

private:
    void report(const std::string& detected, const std::string& expected) {
        if (last_compliant_ != false)
            transitioned_ = true; // compliant/unknown → drifted
        // Poll-originated identical repeat: same verdict as the last emission
        // with no intervening compliant edge — suppress (Gate-8 F1). A CHANGED
        // detected/expected value (e.g. a different bad hash) still reports.
        if (poll_eval_ && last_compliant_ == false && detected == last_detected_ &&
            expected == last_expected_) {
            return;
        }
        last_compliant_ = false; // drifted / can't-verify (reported, possibly collapsed)
        last_detected_ = detected;
        last_expected_ = expected;
        const auto now = std::chrono::steady_clock::now();
        if (last_emit_ && (now - *last_emit_) < std::chrono::milliseconds(cfg_.event_debounce_ms)) {
            ++suppressed_; // fold into the next post-window emission
            return;
        }
        GuardDrift d;
        d.guard_type = "file";
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.detected_value = detected;
        d.expected_value = expected;
        d.collapsed_count = suppressed_;
        suppressed_ = 0;
        last_emit_ = now;
        if (sink_)
            sink_(d);
    }

    // Compliant edge (Slice B): emit guard.compliant ONCE on the transition into
    // compliant (incl. the first eval / baseline-on-arm, last_compliant == nullopt).
    // Steady compliant state is silent; bypasses the drift-debounce collapse.
    void report_compliant() {
        if (last_compliant_ == true)
            return;
        if (last_compliant_ == false)
            transitioned_ = true; // drifted → compliant (a cleared drift)
        last_compliant_ = true;
        last_detected_.clear(); // a fresh drift after this edge must re-report
        last_expected_.clear();
        GuardDrift d;
        d.guard_type = "file";
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.detected_value = "<compliant>";
        d.expected_value = "<compliant>";
        d.compliant = true;
        if (sink_)
            sink_(d);
    }

    const FileGuard::Config& cfg_;
    const GuardSink& sink_;
    const bool hash_mode_;
    const std::filesystem::path target_;

    // Collapse-with-count debounce state.
    std::optional<std::chrono::steady_clock::time_point> last_emit_;
    std::uint64_t suppressed_ = 0;
    // Compliance-edge state: nullopt until the first eval.
    std::optional<bool> last_compliant_;
    // Poll-eval bookkeeping (Gate-8 F1/F3): the last EMITTED drift verdict (for
    // identical-repeat suppression during polls) and whether the current eval
    // flipped compliance state.
    std::string last_detected_;
    std::string last_expected_;
    bool poll_eval_ = false;
    bool transitioned_ = false;
    // file-hash-equals state.
    std::string baseline_; // captured-on-arm hash when expected_hash is empty
    bool baseline_set_ = false;
};

} // namespace
} // namespace yuzu::agent

#endif // _WIN32 || __APPLE__

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "guard_win_handle.hpp"

#include <algorithm>
#include <cstddef>
#include <string>

namespace yuzu::agent {
namespace {

// Degraded re-arm cadence used ONLY when no watch (dir or ancestor) could be armed
// — a rare failure. Without it the INFINITE wait would block forever, silently
// breaking live-until-disabled (mirrors RegistryGuard's kArmFailRetryMs). The
// healthy path never uses this — it stays fully event-driven (no poll).
constexpr DWORD kArmFailRetryMs = 30000;

// (A dead, uncalled local to_wide copy was removed here in the #1681 win_str
// de-dup — guard_file does no wide<->UTF-8 conversion of its own.)

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

    canonicalize_target_path(cfg_);

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

void FileGuard::run() try {
    using detail::ChangeNotifyHandle;
    using detail::DirHandle;
    using detail::EventHandle;
    namespace fs = std::filesystem;
    const fs::path target(cfg_.path);
    const fs::path parent = target.parent_path();
    const std::wstring fname = target.filename().wstring();
    const bool hash_mode = (cfg_.assertion == Assertion::HashEquals);

    // ReadDirectoryChangesW notification buffer (DWORD-aligned). 32 KiB holds many
    // records; on overflow we reconcile unconditionally, so the size is a perf knob
    // not a correctness one.
    alignas(DWORD) std::byte notify_buf[32 * 1024];

    // RAII owners — released on EVERY exit, including an exception unwind (the sink
    // does a network write and can throw); a leaked HANDLE + std::terminate is what
    // the manual-cleanup version risked.
    EventHandle dir_event(CreateEventW(nullptr, FALSE, FALSE, nullptr)); // auto-reset OVERLAPPED hEvent
    if (!dir_event) {
        spdlog::error("Guardian FileGuard[{}]: CreateEventW failed — watch not started", cfg_.rule_id);
        return;
    }
    OVERLAPPED ov{};
    ov.hEvent = dir_event.get();
    DirHandle h_dir;                   // parent dir, open for ReadDirectoryChangesW
    ChangeNotifyHandle ancestor_event; // FindFirstChangeNotificationW (normalises -1 → empty)
    bool read_pending = false;

    // Evaluate/report state machine (debounce, compliant edges, assertions) —
    // platform-neutral, shared with the macOS loop.
    FileEvaluator ev(cfg_, sink_, hash_mode);

    bool hash_pending = false; // a change is settling before we (re)hash
    std::chrono::steady_clock::time_point settle_first{}; // when the current settle window began
    bool arm_retry = false;    // no watch could be armed → degraded bounded re-arm scheduled

    auto reset_dir = [&](HANDLE h = nullptr) {
        h_dir.reset(h);
        read_pending = false;
    };

    // (Re)issue ReadDirectoryChangesW on the already-open parent handle.
    auto arm_dir_read = [&]() -> bool {
        if (!h_dir)
            return false;
        constexpr DWORD kFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                  FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                                  FILE_NOTIFY_CHANGE_CREATION;
        read_pending = ReadDirectoryChangesW(h_dir.get(), notify_buf, sizeof(notify_buf), FALSE,
                                             kFilter, nullptr, &ov, nullptr) != 0;
        return read_pending;
    };

    // Re-resolve the watch from scratch (no eval): arm the parent-dir watch if the
    // parent exists, else the nearest-ancestor watch for its (re)creation. Sets
    // arm_retry when NEITHER could be armed so the wait loop self-heals.
    auto arm_watch = [&] {
        reset_dir();
        ancestor_event.reset();
        arm_retry = false;
        std::error_code ec;
        if (!parent.empty() && fs::is_directory(parent, ec)) {
            reset_dir(CreateFileW(parent.wstring().c_str(), FILE_LIST_DIRECTORY,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                  nullptr));
            if (h_dir && !arm_dir_read())
                reset_dir();
        }
        if (!h_dir) {
            fs::path anc = parent;
            std::error_code ec2;
            while (!anc.empty() && !fs::is_directory(anc, ec2))
                anc = anc.parent_path();
            if (!anc.empty())
                ancestor_event.reset(FindFirstChangeNotificationW(
                    anc.wstring().c_str(), TRUE,
                    FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_FILE_NAME));
            if (!h_dir && !ancestor_event) {
                arm_retry = true; // both arms failed → bounded degraded re-arm (no deaf-forever)
                spdlog::warn("Guardian FileGuard[{}]: no watch armed for {} — degraded re-arm in {}ms",
                             cfg_.rule_id, cfg_.path, kArmFailRetryMs);
            }
        }
    };

    auto begin_settle = [&] {
        if (!hash_pending) {
            hash_pending = true;
            settle_first = std::chrono::steady_clock::now();
        }
    };

    // True iff the completed read mentions our target filename (or overflowed). The
    // record walk is bounded by `bytes` so a malformed/truncated buffer cannot run
    // past the data the kernel actually returned.
    auto change_is_ours = [&](DWORD bytes) -> bool {
        if (bytes == 0)
            return true; // buffer overflow — can't tell, reconcile
        std::size_t off = 0;
        while (off + offsetof(FILE_NOTIFY_INFORMATION, FileName) <= bytes) {
            auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(notify_buf + off);
            const std::size_t name_bytes = info->FileNameLength;
            if (off + offsetof(FILE_NOTIFY_INFORMATION, FileName) + name_bytes > bytes)
                break; // truncated record — stop
            const std::wstring_view name(info->FileName, name_bytes / sizeof(WCHAR));
            if (iequals_w(name, fname))
                return true;
            if (info->NextEntryOffset == 0)
                break;
            off += info->NextEntryOffset;
        }
        return false;
    };

    spdlog::info("Guardian FileGuard[{}]: watching {} ({}) [resilient]", cfg_.rule_id, cfg_.path,
                 hash_mode ? "hash-equals"
                           : (cfg_.expect_present ? "expect present" : "expect absent"));
    arm_watch();
    ev.eval_now(); // initial compare (hash: baseline-on-arm or compare to expected)

    while (!stop_.load(std::memory_order_acquire)) {
        HANDLE handles[3];
        DWORD n = 0;
        const DWORD idx_dir = read_pending ? n : 0xFFFFFFFF;
        if (idx_dir != 0xFFFFFFFF)
            handles[n++] = dir_event.get();
        const DWORD idx_anc = ancestor_event ? n : 0xFFFFFFFF;
        if (idx_anc != 0xFFFFFFFF)
            handles[n++] = ancestor_event.get();
        const DWORD idx_stop = n;
        handles[n++] = static_cast<HANDLE>(stop_event_);

        // Timeout selection (no busy-poll): a settling hash change uses the settle
        // window, but bounded by max_settle_defer so a continuous write storm cannot
        // starve the hash forever (UP-1); a failed-to-arm watch uses a degraded retry;
        // otherwise block on OS events.
        DWORD timeout = INFINITE;
        if (hash_mode && hash_pending) {
            const auto deferred = std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::steady_clock::now() - settle_first)
                                      .count();
            const std::uint64_t cap_left =
                deferred >= static_cast<long long>(cfg_.max_settle_defer_ms)
                    ? 0
                    : cfg_.max_settle_defer_ms - static_cast<std::uint64_t>(deferred);
            timeout = static_cast<DWORD>(std::min<std::uint64_t>(cfg_.settle_ms, cap_left));
        } else if (arm_retry) {
            timeout = kArmFailRetryMs;
        }

        const DWORD r = WaitForMultipleObjects(n, handles, FALSE, timeout);
        if (r == WAIT_OBJECT_0 + idx_stop)
            break;
        if (r == WAIT_TIMEOUT) {
            if (hash_mode && hash_pending) {
                // Settle quiesced (or the max-defer cap fired) → hash now, then
                // re-resolve the watch (handles a parent deleted during the write).
                hash_pending = false;
                ev.eval_hash();
                arm_watch();
            } else if (arm_retry) {
                arm_watch(); // degraded re-arm
                ev.eval_now();
            }
            continue;
        }
        if (idx_dir != 0xFFFFFFFF && r == WAIT_OBJECT_0 + idx_dir) {
            DWORD bytes = 0;
            const BOOL got = GetOverlappedResult(h_dir.get(), &ov, &bytes, FALSE);
            read_pending = false;
            // On a GetOverlappedResult failure we can't trust the buffer → reconcile.
            const bool ours = (got == FALSE) || change_is_ours(bytes);
            if (!ours) {
                if (!arm_dir_read())
                    arm_watch(); // re-arm failed (dir gone) → rebuild
            } else if (hash_mode) {
                // Defer the (expensive, mid-write-prone) hash to the settle timeout;
                // keep the read armed and (re)start the bounded settle countdown.
                if (!arm_dir_read())
                    arm_watch();
                begin_settle();
            } else {
                arm_watch(); // existence: re-resolve + evaluate now
                ev.eval_exists();
            }
        } else if (idx_anc != 0xFFFFFFFF && r == WAIT_OBJECT_0 + idx_anc) {
            arm_watch();
            if (hash_mode)
                begin_settle(); // settle, then hash the (re)created file
            else
                ev.eval_exists();
        } else {
            spdlog::error("Guardian FileGuard[{}]: WaitForMultipleObjects failed (r={}, err={}) — "
                          "watch stopping",
                          cfg_.rule_id, r, GetLastError());
            break; // WAIT_FAILED / WAIT_ABANDONED — unrecoverable
        }
    }
    // RAII: dir_event / h_dir / ancestor_event released by their destructors.
} catch (const std::exception& e) {
    spdlog::error("Guardian FileGuard[{}]: watch thread exception: {} — watch stopping", cfg_.rule_id,
                  e.what());
} catch (...) {
    spdlog::error("Guardian FileGuard[{}]: watch thread unknown exception — watch stopping",
                  cfg_.rule_id);
}

} // namespace yuzu::agent

#elif defined(__APPLE__)

#include <yuzu/agent/guard_fsevents.hpp>

#include <algorithm>
#include <condition_variable>
#include <expected>
#include <mutex>
#include <string>
#include <string_view>

namespace yuzu::agent {
namespace {

// Degraded re-arm cadence used ONLY when no FSEvents stream (parent or
// ancestor) could be armed — a rare failure (FSEvents accepts not-yet-existing
// paths). Mirrors the Windows kArmFailRetryMs so live-until-disabled never goes
// deaf-forever; the healthy path stays fully event-driven (no poll).
constexpr std::chrono::milliseconds kArmFailRetry{30000};

// Healthy-mode liveness backstop (UP-1/UP-2): an FSEvents stream has no death
// signal — if fseventsd restarts (or the target lives on a network volume whose
// remote-origin changes FSEvents never reports), an untimed wait would be deaf
// forever while the rule reads armed. Re-evaluate on this cadence so the worst
// case degrades to a slow poll, never silence — the same philosophy as the TAR
// ES stream's idle self-heal (docs/darwin-compat.md). Deliberately long: the
// healthy path stays event-driven; this is one cheap stat (exists mode) or one
// bounded hash per 15 minutes.
constexpr std::chrono::milliseconds kIdleRecheck{15 * 60 * 1000};

// Wake state shared between the FSEvents emit callback (core delivery queue),
// stop() (engine thread) and run() (watch thread). Allocated in start() and
// owned through the opaque stop_event_ member; deleted in stop() AFTER the
// join, so run() and the (already-stopped) core can never touch it stale.
struct DarwinWake {
    std::mutex m;
    std::condition_variable cv;
    bool event{false};     // any wake source below fired (the cv predicate)
    bool dir_event{false}; // an attributable dir-stream change touched our target
    bool rearm{false};     // unattributable on the dir stream → re-resolve the watch
    bool anc_event{false}; // the ancestor backstop fired (the parent may now exist)
};

// ASCII case-insensitive equality. APFS is case-insensitive (case-preserving)
// by default, so a "Foo.txt" notification must match a "foo.txt" target. On a
// case-SENSITIVE volume this can only produce a false positive, which merely
// costs one reconcile (state is re-read from disk); a false negative would
// miss drift. Ordinal, ASCII-only — a filename match is a byte identity check,
// not a linguistic one (same rationale as the Windows iequals_w). Names that
// leave ASCII bypass this filter entirely (see has_non_ascii below).
bool iequals_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        char x = a[i];
        char y = b[i];
        if (x >= 'A' && x <= 'Z')
            x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z')
            y = static_cast<char>(y - 'A' + 'a');
        if (x != y)
            return false;
    }
    return true;
}

// APFS case-insensitivity uses Unicode folding tables (with oddities like
// U+017F ſ → s and U+212A K → k) that an ASCII fold cannot reproduce, so two
// byte-different names can still be THE SAME file. Never risk a missed wake on
// that: when either name leaves ASCII, the filename prefilter is bypassed and
// the event treated as ours — a false positive only costs one reconcile.
bool has_non_ascii(std::string_view s) {
    for (unsigned char c : s)
        if (c >= 0x80)
            return true;
    return false;
}

} // namespace

FileGuard::FileGuard(Config cfg, GuardSink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}

FileGuard::~FileGuard() { stop(); }

bool FileGuard::start() {
    if (cfg_.path.empty())
        return false;

    canonicalize_target_path(cfg_);

    stop_event_ = new DarwinWake();
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
    return true;
}

void FileGuard::stop() {
    stop_.store(true, std::memory_order_release);
    if (auto* wake = static_cast<DarwinWake*>(stop_event_)) {
        // Empty critical section: the waiter either sees stop_ before sleeping or
        // is woken by this notify — the classic no-missed-wakeup handshake.
        { std::lock_guard lk(wake->m); }
        wake->cv.notify_all();
    }
    if (thread_.joinable())
        thread_.join();
    delete static_cast<DarwinWake*>(stop_event_); // after join — nothing touches it now
    stop_event_ = nullptr;
}

void FileGuard::run() try {
    namespace fs = std::filesystem;
    const fs::path target(cfg_.path);
    const fs::path parent = target.parent_path();
    const std::string fname = target.filename().string();
    const bool hash_mode = (cfg_.assertion == Assertion::HashEquals);
    auto* wake = static_cast<DarwinWake*>(stop_event_);

    // Evaluate/report state machine (debounce, compliant edges, assertions) —
    // platform-neutral, shared with the Windows loop.
    FileEvaluator ev(cfg_, sink_, hash_mode);

    // Watch the PARENT directory: FileEvents-granularity FSEvents deliver the
    // full path of every changed item under it, filtered to our filename below.
    const std::string dir_path = (parent.empty() ? target : parent).string();
    const bool fname_ascii_only = !has_non_ascii(fname);

    FsEventsWatchCore core;
    core.start(
        // Emit callback — runs on the core's delivery queue: filter, flip the
        // wake flags, notify. Never blocks, never calls back into the core.
        [&dir_path, &fname, fname_ascii_only, wake](const FsWatchEvent& e) {
            // Ancestor-backstop events are only a "parent may exist now" hint —
            // never a reconcile trigger by themselves (the run loop stat-gates
            // them; an absent parent means volume churn is noise, CH-2).
            if (e.key == "anc") {
                {
                    std::lock_guard lk(wake->m);
                    wake->event = true;
                    wake->anc_event = true;
                }
                wake->cv.notify_all();
                return;
            }
            bool ours = e.must_reconcile;
            if (!ours && !e.path.empty()) {
                std::string p = e.path;
                while (p.size() > 1 && p.back() == '/')
                    p.pop_back(); // FSEvents may report directories with a trailing slash
                const std::string base = fs::path(p).filename().string();
                // Ours: the changed item is our target (by name), or the parent
                // dir itself (dir-level event → can't attribute → reconcile; the
                // compare is case-insensitive like the filename one — APFS), or
                // either name leaves ASCII (Unicode folding — see has_non_ascii).
                ours = iequals_ascii(p, dir_path) || iequals_ascii(base, fname) ||
                       !fname_ascii_only || has_non_ascii(base);
            } else if (!ours && e.path.empty()) {
                ours = true; // no path — can't attribute, reconcile
            }
            if (!ours)
                return; // sibling churn — do not wake the evaluator (NFR)
            {
                std::lock_guard lk(wake->m);
                wake->event = true;
                if (e.must_reconcile)
                    wake->rearm = true;
                else
                    wake->dir_event = true; // attributable → must evaluate even if
                                            // coalesced with an anc hint (G8R-2)
            }
            wake->cv.notify_all();
        },
        [this, wake](const std::string& key, const std::string& what) {
            spdlog::warn("Guardian FileGuard[{}]: FSEvents fault on '{}': {} — reconciling",
                         cfg_.rule_id, key, what);
            {
                std::lock_guard lk(wake->m);
                wake->event = true;
                wake->rearm = true;
            }
            wake->cv.notify_all();
        });

    bool arm_retry = false; // no stream could be armed → degraded bounded re-arm

    // Arm the parent-dir stream. A stream armed while its directory exists
    // survives that directory being deleted and recreated (path-string
    // subscription), so unlike Windows no per-wake re-arm is needed. The
    // nearest-existing-ancestor backstop is armed when the parent does not
    // exist YET (delivery on never-existed roots is not a documented FSEvents
    // guarantee) or when the parent stream failed; its events re-trigger
    // arming. If nothing could be armed, schedule the degraded re-arm.
    auto arm_watch = [&] {
        core.unwatch("dir");
        core.unwatch("anc");
        arm_retry = false;
        const auto dir_res = core.watch("dir", dir_path);
        std::error_code ec;
        if (dir_res && fs::is_directory(dir_path, ec))
            return;
        fs::path anc = parent.empty() ? fs::path{} : parent.parent_path();
        while (!anc.empty() && anc != anc.root_path() && !fs::is_directory(anc, ec))
            anc = anc.parent_path();
        // NEVER pin the backstop to the volume root: a FileEvents stream on "/"
        // receives every event on the volume, and each would cost at least a
        // stat here (CH-2 storm). If the nearest existing ancestor IS the root,
        // fall back to the bounded 30s re-arm poll instead.
        const bool anc_usable = !anc.empty() && anc != anc.root_path();
        auto anc_res = !anc_usable
                           ? std::expected<void, std::string>(std::unexpected(
                                 "no usable ancestor (root refused — degraded poll)"))
                           : core.watch("anc", anc.string());
        if (!anc_res) {
            // We only reach here when the parent is absent or the dir stream
            // failed. Without a usable backstop, delivery is not guaranteed
            // even if the dir stream nominally armed (never-existed roots) —
            // degrade to the bounded re-arm poll (no deaf-forever).
            arm_retry = true;
            spdlog::warn("Guardian FileGuard[{}]: degraded watch for {} (dir: {}; ancestor: {}) — "
                         "re-arm in {}ms",
                         cfg_.rule_id, cfg_.path,
                         dir_res ? std::string("armed, parent absent") : dir_res.error(),
                         anc_res.error(), kArmFailRetry.count());
        }
    };

    bool hash_pending = false; // a change is settling before we (re)hash
    bool settle_from_poll = false; // the pending settle was poll-initiated (idle recheck)
    std::chrono::steady_clock::time_point settle_first{}; // when the settle window began

    spdlog::info("Guardian FileGuard[{}]: watching {} ({}) [resilient, FSEvents]", cfg_.rule_id,
                 cfg_.path,
                 hash_mode ? "hash-equals"
                           : (cfg_.expect_present ? "expect present" : "expect absent"));
    arm_watch();
    ev.eval_now(); // initial compare AFTER arming — a change in the arm→check gap re-fires

    std::unique_lock lk(wake->m);
    const auto woken = [&] { return wake->event || stop_.load(std::memory_order_acquire); };
    while (!stop_.load(std::memory_order_acquire)) {
        // Timeout selection (no busy-poll): a settling hash change uses the settle
        // window, but bounded by max_settle_defer so a continuous write storm cannot
        // starve the hash forever (UP-1); a failed-to-arm watch uses a degraded retry;
        // otherwise block on the FSEvents wake, bounded by the idle liveness
        // recheck (kIdleRecheck — silent stream death / network volumes).
        bool woke = true;
        bool idle_recheck = false;
        if (hash_mode && hash_pending) {
            const auto deferred = std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::steady_clock::now() - settle_first)
                                      .count();
            const std::uint64_t cap_left =
                deferred >= static_cast<long long>(cfg_.max_settle_defer_ms)
                    ? 0
                    : cfg_.max_settle_defer_ms - static_cast<std::uint64_t>(deferred);
            const auto timeout =
                std::chrono::milliseconds(std::min<std::uint64_t>(cfg_.settle_ms, cap_left));
            woke = wake->cv.wait_for(lk, timeout, woken);
        } else if (arm_retry) {
            woke = wake->cv.wait_for(lk, kArmFailRetry, woken);
        } else {
            woke = wake->cv.wait_for(lk, kIdleRecheck, woken);
            idle_recheck = !woke;
        }
        if (stop_.load(std::memory_order_acquire))
            break;

        if (!woke) { // timeout — evaluate outside the wake lock (sink does I/O)
            if (hash_mode && hash_pending) {
                hash_pending = false;
                lk.unlock();
                if (settle_from_poll) {
                    settle_from_poll = false;
                    // Poll-initiated settle: identical repeats suppressed; a
                    // state TRANSITION with no stream event means the stream
                    // missed it — re-arm (Gate-8 F3 self-heal).
                    if (ev.eval_poll())
                        arm_watch();
                } else {
                    ev.eval_hash(); // settle quiesced (or the max-defer cap fired)
                }
                lk.lock();
            } else if (arm_retry) {
                lk.unlock();
                arm_watch(); // degraded re-arm
                ev.eval_poll();
                lk.lock();
            } else if (idle_recheck) {
                // Liveness backstop: nothing arrived for kIdleRecheck. Re-read
                // real state. Identical repeat verdicts are suppressed (F1); in
                // hash mode the read goes through the settle window first so a
                // mid-write tick can neither report a torn hash nor baseline
                // one (F2); a transition with no stream event re-arms (F3).
                lk.unlock();
                if (hash_mode) {
                    hash_pending = true;
                    settle_from_poll = true;
                    settle_first = std::chrono::steady_clock::now();
                } else if (ev.eval_poll()) {
                    arm_watch();
                }
                lk.lock();
            }
            continue;
        }

        const bool rearm = wake->rearm;
        const bool anc = wake->anc_event;
        const bool dir_evt = wake->dir_event;
        wake->event = false;
        wake->rearm = false;
        wake->anc_event = false;
        wake->dir_event = false;
        lk.unlock();
        bool armed_now = false;
        if (rearm) {
            arm_watch(); // unattributable / fault → re-resolve from scratch
            armed_now = true;
        } else if (anc) {
            // Ancestor-backstop hint: only meaningful if the parent now exists —
            // then re-arm the dir stream. While the parent is still absent this
            // is volume churn under the ancestor: one stat, no stream teardown
            // (the CH-2 storm damper). A genuine coalesced dir event still
            // evaluates below via dir_evt (G8R-2).
            std::error_code ec;
            if (fs::is_directory(dir_path, ec)) {
                arm_watch();
                armed_now = true;
            }
        }
        if (dir_evt || armed_now) {
            if (hash_mode) {
                // Defer the (expensive, mid-write-prone) hash to the settle
                // timeout; each further change restarts the (bounded) settle
                // countdown. An event-driven change supersedes any pending
                // poll-initiated settle's suppression semantics.
                if (!hash_pending) {
                    hash_pending = true;
                    settle_first = std::chrono::steady_clock::now();
                }
                settle_from_poll = false;
            } else {
                ev.eval_exists();
            }
        }
        lk.lock();
    }
    lk.unlock();
    // Join the delivery queue BEFORE run() returns: no emit may outlive this
    // frame (the callback captures dir_path/fname/wake). ~FsEventsWatchCore
    // would do it too — explicit for the reader.
    core.stop();
} catch (const std::exception& e) {
    spdlog::error("Guardian FileGuard[{}]: watch thread exception: {} — watch stopping", cfg_.rule_id,
                  e.what());
} catch (...) {
    spdlog::error("Guardian FileGuard[{}]: watch thread unknown exception — watch stopping",
                  cfg_.rule_id);
}

} // namespace yuzu::agent

#else // Linux — no-op (inotify is later platform work)

namespace yuzu::agent {

FileGuard::FileGuard(Config cfg, GuardSink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}
FileGuard::~FileGuard() = default;
bool FileGuard::start() { return false; } // file-change Spark is Windows/macOS-only today
void FileGuard::stop() {}
void FileGuard::run() {}

} // namespace yuzu::agent

#endif // _WIN32 / __APPLE__
