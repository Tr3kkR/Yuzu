/**
 * spark_file.cpp — the File spark mechanism (ADR-0021 Stage 1 PR 1b).
 *
 * Windows: one IOCP + one worker thread multiplexing ReadDirectoryChangesW
 * across every watched PARENT DIRECTORY — O(mechanism), never O(rules). Two
 * file sparks in the same directory share one ReadDirectoryChangesW
 * registration; a raw directory notification is routed back to the matching
 * spark key(s) by changed filename. IOCP (not WaitForMultipleObjects) is
 * deliberate: the 64-handle MAXIMUM_WAIT_OBJECTS cap is exactly the O(rules)
 * ceiling the SparkEngine exists to remove (the trigger_engine registry-poll
 * mistake).
 *
 * This mechanism PORTS THE WATCH, NOT THE ASSERTION. Unlike guard_file.cpp it
 * does NO expected-value compare, NO hashing, NO write-back — a fired spark is
 * a raw "this path changed" fact (the old TriggerEngine FileChange trigger
 * shape). The compare + enforce move to Guardian as an inline consumer in
 * Stage 2. It DOES port guard_file's watch-resilience: the nearest-existing-
 * ancestor watch that survives a deleted+recreated parent, and arm-before-check
 * ordering (ReadDirectoryChangesW issued before anything reads state).
 *
 * Off Windows the factory returns nullptr: the SparkEngine then rejects
 * arm(File) (spark.hpp: armed == a watcher is running).
 */

#include "spark_mechanism.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "guard_win_handle.hpp" // detail::DirHandle, detail::EventHandle

#include <spdlog/spdlog.h>

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cwctype>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace yuzu::agent {
namespace {

namespace fs = std::filesystem;

using detail::DirHandle;

constexpr DWORD kFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                          FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                          FILE_NOTIFY_CHANGE_CREATION;

// Completion-key sentinels distinguish a directory completion (key == the
// DirWatch pointer) from a control wake (watch/unwatch/stop posted the queue).
constexpr ULONG_PTR kControlKey = 0;

// Locale-INDEPENDENT case fold for directory + filename matching (sec-M1).
// NTFS is case-insensitive via an upcase table; guard_file.cpp matches changed
// names with CompareStringOrdinal(...,TRUE). The previous per-wchar ::towlower is
// C-locale (ASCII-only), so a non-ASCII filename differing only in case between
// the spark's watched name and the FILE_NOTIFY_INFORMATION name would MISS — a
// silently dropped spark (fail-open detection, worse than a crash for a Stage-2
// enforce consumer). LCMapStringEx with the INVARIANT locale folds the full
// Unicode range deterministically, matching NTFS case-insensitive semantics.
std::wstring fold_ci(std::wstring_view s) {
    if (s.empty())
        return {};
    const int n = ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.data(),
                                  static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr, 0);
    if (n <= 0)
        return std::wstring(s); // fold unavailable → exact match (safe; only over-strict on case)
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.data(), static_cast<int>(s.size()),
                    out.data(), n, nullptr, nullptr, 0);
    return out;
}

/// One watched directory: its overlapped read, its buffer, and the set of spark
/// keys interested in each (lower-cased) filename inside it. Heap-owned and
/// kept alive until its outstanding I/O drains — the IOCP teardown contract.
struct DirWatch {
    DirHandle handle;               ///< CreateFileW(FILE_LIST_DIRECTORY, OVERLAPPED), IOCP-associated
    OVERLAPPED ov{};                ///< distinct per dir — the IOCP key back to this struct
    alignas(DWORD) std::byte buf[32 * 1024]; ///< FILE_NOTIFY_INFORMATION landing buffer
    std::wstring dir;               ///< normalised absolute directory path
    std::unordered_map<std::wstring, std::unordered_set<std::string>> keys; ///< fname → spark keys
    bool io_pending{false};         ///< a ReadDirectoryChangesW is outstanding
    bool removing{false};           ///< unwatch drained this dir; free once the last I/O returns
    // Ancestor bookkeeping (S1: ancestors_ otherwise leak on churn).
    int refcount{0};             ///< ancestor watch: # of absent dirs depending on it
    std::wstring ancestor_key;   ///< real dir: which ancestor it currently depends on ("" = none)
    bool faulted{false};         ///< real dir: last health reported through the fault channel (B1)
};

/// Windows file-change mechanism. Thread-safe: watch/unwatch (engine threads)
/// and the worker all take `mu_`. ReadDirectoryChangesW is async, so re-arming
/// under `mu_` is cheap; CreateFileW in watch() runs on the engine's arm path
/// (already off the engine lock).
class WindowsFileMechanism final : public ISparkMechanism {
public:
    /// Bounds retiring_ growth under re-arm churn faster than the single
    /// worker thread can drain (#1979). ~256 * sizeof(DirWatch) (dominated by
    /// the 32 KiB notify buffer) is worst-case ~8.5 MiB pinned — generous
    /// against real churn, small against unbounded growth.
    static constexpr std::size_t kRetiringCap = 256;

    ~WindowsFileMechanism() override { stop(); }

    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        std::lock_guard lk(mu_);
        if (iocp_)
            return; // idempotent
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        iocp_.reset(::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, kControlKey, 1));
        if (!iocp_) {
            spdlog::error("spark_file: CreateIoCompletionPort failed (err={}) — file sparks inert",
                          ::GetLastError());
            // Publish it: a registered-but-inert mechanism must not report as a live
            // capability (governance Gate-3 cross-platform / Gate-6 sre).
            inert_.store(true, std::memory_order_release);
            return;
        }
        inert_.store(false, std::memory_order_release);
        stop_.store(false, std::memory_order_release);
        worker_ = std::thread([this] { run(); });
    }

    std::expected<void, std::string> watch(const std::string& key,
                                           const SparkParams& params) override {
        const auto* fp = std::get_if<FileSparkParams>(&params);
        if (!fp)
            return std::unexpected("file mechanism: params are not FileSparkParams");
        fs::path target = fs::path(fp->path);
        fs::path parent = target.has_parent_path() ? target.parent_path() : fs::current_path();
        const std::wstring fname = fold_ci(target.filename().wstring());
        const std::wstring dirkey = fold_ci(parent.wstring());

        std::lock_guard lk(mu_);
        if (!iocp_)
            return std::unexpected("file mechanism not started");
        // #1979: refuse NEW work while too many cancelled watches are still
        // awaiting their drained IOCP completion — re-arm churn faster than
        // the single worker thread can drain would otherwise grow retiring_
        // unbounded. Teardown (unwatch/release_ancestor below) is NEVER
        // gated — only this entry point, which is the sole producer of new
        // pending-I/O DirWatches, so the cap bounds growth even though
        // retiring_ can transiently exceed it while in-flight teardowns land.
        if (retiring_.size() >= kRetiringCap) {
            watch_rejected_.fetch_add(1, std::memory_order_relaxed);
            return std::unexpected(
                std::string("file mechanism: ") + std::to_string(retiring_.size()) +
                " watch(es) awaiting IOCP teardown (cap " + std::to_string(kRetiringCap) +
                ") — arm refused");
        }
        // #1981: a re-arm of THIS key against a DIFFERENT (dirkey, fname) than
        // its current registration — e.g. an authored path change on config
        // reload/redeploy, with no intervening explicit unwatch(key) — must
        // not silently overwrite key_index_[key] below: the OLD registration
        // in the abandoned DirWatch::keys[old_fname] would never be cleaned
        // up, so that entry keeps firing this key from the old path forever
        // (a permanent per-key leak). Implicitly clear the stale registration
        // first, exactly as if the caller had unwatch()'d it. A same-
        // (dirkey, fname) re-arm is unaffected — key_index_'s stored pair
        // already matches, so this is a no-op (idempotent).
        if (auto ki = key_index_.find(key);
            ki != key_index_.end() && ki->second != std::pair{dirkey, fname}) {
            unwatch_locked(key);
        }
        auto& slot = dirs_[dirkey];
        if (!slot) {
            slot = std::make_unique<DirWatch>();
            slot->dir = parent.wstring();
            if (!arm_dir(*slot)) {
                // Directory absent/unopenable: keep the (empty-of-I/O) entry so
                // the key is recorded, and watch the nearest ancestor for the
                // parent's (re)creation. arm_ancestor is best-effort + refcounted.
                arm_ancestor(*slot);
            }
        }
        slot->keys[fname].insert(key);
        key_index_[key] = {dirkey, fname};
        return {};
    }

    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        unwatch_locked(key);
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            if (!iocp_)
                return;
        }
        stop_.store(true, std::memory_order_release);
        // Wake the worker out of GetQueuedCompletionStatus.
        ::PostQueuedCompletionStatus(iocp_.get(), 0, kControlKey, nullptr);
        if (worker_.joinable())
            worker_.join();
        std::lock_guard lk(mu_);
        // F2: the worker is joined, but a ReadDirectoryChangesW may still be
        // outstanding — the kernel writes into buf/ov until it completes, so a
        // bare CloseHandle+free races that write (UAF). Cancel every outstanding
        // read across ALL three containers (dirs_, ancestors_, retiring_ — the
        // prior code cleared only dirs_, leaking ancestor handles) and then REAP
        // the cancelled completions from the IOCP before freeing.
        //
        // Reap via GetQueuedCompletionStatus, NOT GetOverlappedResult(wait=TRUE):
        // the completion of an IOCP-associated handle is delivered to the PORT,
        // and the dir OVERLAPPED has no hEvent, so GetOverlappedResult(TRUE) would
        // wait on a handle that is never signaled → deadlock (caught on DGRHP).
        // CancelIoEx makes each read complete promptly (ERROR_OPERATION_ABORTED),
        // so one packet per outstanding read lands on the port; dequeue exactly
        // that many (skipping our control wake), with a bounded wait so a lost
        // completion can never hang shutdown.
        std::size_t pending = 0;
        auto cancel = [&](DirWatch& w) {
            if (w.handle && w.io_pending) {
                ::CancelIoEx(w.handle.get(), &w.ov);
                ++pending;
            }
        };
        for (auto& [k, w] : dirs_)
            cancel(*w);
        for (auto& [k, w] : ancestors_)
            cancel(*w);
        for (auto& w : retiring_)
            cancel(*w);
        bool lost_completion = false;
        while (pending > 0) {
            DWORD bytes = 0;
            ULONG_PTR ckey = 0;
            LPOVERLAPPED ov = nullptr;
            const BOOL ok = ::GetQueuedCompletionStatus(iocp_.get(), &bytes, &ckey, &ov, 2000);
            if (!ok && ov == nullptr) {
                lost_completion = true; // 2s with no packet — a completion was lost
                break;
            }
            if (ckey == kControlKey)
                continue; // our own PostQueuedCompletionStatus wake(s)
            --pending;    // a cancelled/normal read drained — kernel is done with its buf/ov
        }
        if (lost_completion) {
            // A cancelled read's completion never arrived within the budget, so a
            // read may still be live — the kernel could still write its buf/ov.
            // Freeing it would be a use-after-free (governance UP2-4). Instead
            // QUARANTINE every still-outstanding watch to PROCESS lifetime: its
            // handle stays open and its buf/ov live forever, so a late kernel
            // write is harmless. A bounded shutdown-only leak, only on this
            // near-unreachable path (CancelIoEx on an open IOCP handle normally
            // posts a prompt ABORTED packet), is the safe trade vs a UAF.
            static std::vector<std::unique_ptr<DirWatch>> s_quarantine;
            std::size_t leaked = 0;
            for (auto it = dirs_.begin(); it != dirs_.end();) {
                if (it->second && it->second->io_pending) {
                    s_quarantine.push_back(std::move(it->second));
                    it = dirs_.erase(it);
                    ++leaked;
                } else {
                    ++it;
                }
            }
            for (auto it = ancestors_.begin(); it != ancestors_.end();) {
                if (it->second && it->second->io_pending) {
                    s_quarantine.push_back(std::move(it->second));
                    it = ancestors_.erase(it);
                    ++leaked;
                } else {
                    ++it;
                }
            }
            for (auto& w : retiring_)
                if (w && w->io_pending) {
                    s_quarantine.push_back(std::move(w));
                    ++leaked;
                }
            spdlog::error("spark_file: shutdown drain lost a completion — quarantined {} "
                          "outstanding watch(es) to process lifetime to avoid a UAF",
                          leaked);
            quarantined_.fetch_add(leaked, std::memory_order_relaxed);
        }
        dirs_.clear();
        ancestors_.clear();
        // Every entry still in retiring_ at this point is about to be freed
        // (safely-drained) or was already moved to s_quarantine above — either
        // way it's no longer "awaiting a drained completion" (#1979).
        retiring_gauge_.fetch_sub(retiring_.size(), std::memory_order_relaxed);
        retiring_.clear();
        iocp_.reset();
        emit_ = nullptr;
        fault_ = nullptr;
    }

    /// Lock-free — callable from any thread without coordinating with mu_
    /// (#1979).
    [[nodiscard]] SparkMechanismStats stats() const override {
        return {
            .retiring = retiring_gauge_.load(std::memory_order_relaxed),
            .retiring_cap = kRetiringCap,
            .watch_rejected_total = watch_rejected_.load(std::memory_order_relaxed),
            .quarantined_total = quarantined_.load(std::memory_order_relaxed),
            .slow_op_total = slow_op_.load(std::memory_order_relaxed),
            .inert = inert_.load(std::memory_order_acquire),
        };
    }

private:
    /// Move a cancelled-but-still-io_pending DirWatch into retiring_, bumping
    /// the gauge and warning once per cap/2 crossing (#1979) — the single
    /// choke point unwatch_locked() and release_ancestor() both route a
    /// cancelled DirWatch through, so the gauge and the cap in watch() stay
    /// consistent with each other regardless of which caller triggered it.
    void push_retiring(std::unique_ptr<DirWatch> w) {
        retiring_.push_back(std::move(w));
        if (retiring_gauge_.fetch_add(1, std::memory_order_relaxed) + 1 == kRetiringCap / 2)
            spdlog::warn("spark_file: retiring_ crossed {} of {} pending IOCP teardowns",
                         kRetiringCap / 2, kRetiringCap);
    }

    /// Core of unwatch(); ASSUMES mu_ IS ALREADY HELD. Also called by watch()
    /// to implicitly clear a stale key_index_ registration before re-arming
    /// the same key against a different (dirkey, fname) — see watch() (#1981).
    void unwatch_locked(const std::string& key) {
        auto ki = key_index_.find(key);
        if (ki == key_index_.end())
            return;
        const auto [dirkey, fname] = ki->second;
        key_index_.erase(ki);
        auto di = dirs_.find(dirkey);
        if (di == dirs_.end())
            return;
        DirWatch& w = *di->second;
        auto fi = w.keys.find(fname);
        if (fi != w.keys.end()) {
            fi->second.erase(key);
            if (fi->second.empty())
                w.keys.erase(fi);
        }
        if (w.keys.empty()) {
            // No spark cares about this dir any more. Drop its ancestor dependency
            // (S1) first, then free. If an I/O is outstanding, cancel it and let
            // the worker free the DirWatch when the (aborted) completion drains —
            // never free memory a pending completion points at. Else drop now.
            release_ancestor(w);
            // Guard shape matches release_ancestor's below exactly (io_pending
            // implies handle everywhere in this file, but check both so the
            // two "same pattern" sites stay textually identical — governance
            // Gate-4 consistency finding).
            if (w.io_pending && w.handle) {
                w.removing = true;
                ::CancelIoEx(w.handle.get(), &w.ov);
                // Free dirkey for reuse NOW — a watch() racing this unwatch()
                // must get a fresh DirWatch, never resurrect this one (it's
                // already been told to die and will be freed by drop_watch()
                // when the aborted completion drains). Leaving it keyed in
                // dirs_ let a same-dir re-arm silently insert into a watch
                // that's about to be freed — arm() reports success but there
                // is no live ReadDirectoryChangesW behind it (governance
                // finding, PR #1927 review), matching release_ancestor's
                // existing retiring_ pattern above.
                push_retiring(std::move(di->second));
                dirs_.erase(di);
            } else {
                dirs_.erase(di);
            }
        }
    }

    /// If `t0` (the caller's entry time) to now exceeds 100ms, bump slow_op_
    /// and warn (#1980). Both arm_dir() and arm_ancestor() run under mu_ (the
    /// mechanism's only lock) and can block on a slow/unresponsive filesystem
    /// path — this is an early warning sign of a stalled watcher, not a hard
    /// fault, so it never changes behavior, only observability. slow_op_total
    /// is an APPROXIMATE early-warning gauge, not an exact count: a single slow
    /// ancestor-arm can be counted twice because arm_ancestor's guard wraps the
    /// nested arm_dir() call which has its own guard. Treat non-zero as "a watch
    /// arm is stalling — investigate", not as a precise event tally.
    void note_if_slow(std::chrono::steady_clock::time_point t0, const char* what,
                      const std::wstring& dir) {
        const auto elapsed = std::chrono::steady_clock::now() - t0;
        if (elapsed <= std::chrono::milliseconds(100))
            return;
        slow_op_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("spark_file: {} for '{}' took {}ms — possible stalled/unresponsive path",
                     what, fs::path(dir).string(),
                     std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    }

    /// Issue (or re-issue) the overlapped ReadDirectoryChangesW for `w`. Opens
    /// the directory handle + associates it with the IOCP on first arm. Returns
    /// false if the directory can't be opened (caller falls back to ancestor).
    bool arm_dir(DirWatch& w) {
        const auto t0 = std::chrono::steady_clock::now();
        struct Guard {
            WindowsFileMechanism* self;
            std::chrono::steady_clock::time_point t0;
            const std::wstring* dir;
            ~Guard() { self->note_if_slow(t0, "arm_dir", *dir); }
        } guard{this, t0, &w.dir};
        if (!w.handle) {
            std::error_code ec;
            if (!fs::is_directory(w.dir, ec))
                return false;
            DirHandle h(::CreateFileW(
                w.dir.c_str(), FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));
            if (!h)
                return false;
            if (!::CreateIoCompletionPort(h.get(), iocp_.get(),
                                          reinterpret_cast<ULONG_PTR>(&w), 0)) {
                spdlog::error("spark_file: IOCP associate failed for {} (err={})",
                              fs::path(w.dir).string(), ::GetLastError());
                return false;
            }
            w.handle = std::move(h);
        }
        // Arm-before-check: the read is outstanding before anyone reads state.
        w.io_pending = ::ReadDirectoryChangesW(w.handle.get(), w.buf, sizeof(w.buf), FALSE, kFilter,
                                               nullptr, &w.ov, nullptr) != 0;
        if (!w.io_pending)
            w.handle.reset(); // dir vanished between open and read → treat as absent
        return w.io_pending;
    }

    /// Best-effort: point `dependent` (a real dir whose parent is absent) at a
    /// watch on the nearest existing ancestor, so a (re)created parent re-arms it.
    /// Refcounts the shared ancestor watch (S1). Returns true if an ancestor is
    /// being watched for it. Idempotent when the ancestor is unchanged.
    bool arm_ancestor(DirWatch& dependent) {
        const auto t0 = std::chrono::steady_clock::now();
        struct Guard {
            WindowsFileMechanism* self;
            std::chrono::steady_clock::time_point t0;
            const std::wstring* dir;
            ~Guard() { self->note_if_slow(t0, "arm_ancestor", *dir); }
        } guard{this, t0, &dependent.dir};

        fs::path anc = fs::path(dependent.dir);
        std::error_code ec;
        // parent_path() of a root (drive root, UNC share root) returns itself —
        // a fixed point, not empty — so for a root that doesn't exist (a gone
        // drive, an unreachable UNC share) the naive "walk until empty" loop
        // never terminates while holding mu_, bricking the mechanism and
        // hanging shutdown behind it (governance finding, PR #1927 review).
        // Stop at the fixed point — analogous to (not a literal port of)
        // spark_registry.cpp's open_nearest_ancestor guard: registry's walk
        // is a pure string truncation with no fixed point (it terminates by
        // reaching "", the case that guard is built around), so copying just
        // its "guard on emptiness" shape would NOT have fixed this hang — a
        // rooted fs::path's parent is itself, never empty (governance Gate-4
        // consistency finding, PR #1927 review).
        //
        // #1980: each fs::is_directory probe can itself block for the OS's
        // network timeout on a dead/unresponsive UNC path — the fixed-point
        // guard above stops an INFINITE loop, but not a SLOW one. A deadline,
        // checked every iteration, caps the walk at one-probe-past-500ms
        // instead of depth × per-probe-timeout. IMPORTANT (unhappy-path UP-1):
        // this bounds the NUMBER of slow probes to ~one, NOT the wall-clock of
        // any single probe — the deadline is checked BETWEEN probes, and
        // fs::is_directory is uninterruptible, so one hung probe on a dead path
        // still holds mu_ for the full OS network timeout before this check
        // fires. It is strictly better than the prior infinite hang, but it is
        // NOT a ~500ms wall-clock bound; truly bounding it needs to move the
        // probe off mu_ onto a separate thread (deferred follow-up).
        for (fs::path prev; !anc.empty() && anc != prev && !fs::is_directory(anc, ec);) {
            if (std::chrono::steady_clock::now() - t0 > std::chrono::milliseconds(500)) {
                // NOT slow_op_.fetch_add here — the `guard` above already counts
                // this via note_if_slow on scope exit (elapsed > 500ms > 100ms),
                // so an explicit increment would double-count (cpp-safety Gate 3).
                // Keep only the abandon-specific warn, which is more informative
                // than note_if_slow's generic ">Nms" line.
                spdlog::warn("spark_file: ancestor walk from '{}' exceeded 500ms — abandoning "
                             "(a path on this chain may be an unresponsive network share)",
                             fs::path(dependent.dir).string());
                release_ancestor(dependent);
                return false;
            }
            prev = anc;
            anc = anc.parent_path();
        }
        if (anc.empty() || !fs::is_directory(anc, ec)) {
            release_ancestor(dependent);
            return false;
        }
        const std::wstring akey = fold_ci(anc.wstring());
        if (dependent.ancestor_key == akey)
            return true; // already depending on exactly this ancestor — no churn
        release_ancestor(dependent);
        auto& slot = ancestors_[akey];
        if (!slot) {
            slot = std::make_unique<DirWatch>();
            slot->dir = anc.wstring();
            if (!arm_dir(*slot)) {
                ancestors_.erase(akey);
                return false;
            }
        }
        slot->refcount++;
        dependent.ancestor_key = akey;
        return true;
    }

    /// Drop `dependent`'s dependency on its ancestor watch; tear the ancestor down
    /// when no absent dir still needs it (S1 — ancestors_ otherwise leak forever).
    void release_ancestor(DirWatch& dependent) {
        if (dependent.ancestor_key.empty())
            return;
        auto it = ancestors_.find(dependent.ancestor_key);
        dependent.ancestor_key.clear();
        if (it == ancestors_.end())
            return;
        if (--it->second->refcount > 0)
            return; // another absent dir still depends on this ancestor
        // Last dependent gone. If a read is outstanding, an IOCP packet still
        // references its &ov, so the worker must free it on the drained completion
        // — move it to retiring_ (freeing the map key for reuse) and mark removing.
        // Otherwise drop it now.
        if (it->second->handle && it->second->io_pending) {
            it->second->removing = true;
            ::CancelIoEx(it->second->handle.get(), &it->second->ov);
            push_retiring(std::move(it->second));
        }
        ancestors_.erase(it);
    }

    /// Record a health transition for every key in a real dir `w` (B1). Faults are
    /// fired by the caller AFTER releasing mu_. No-op when the state is unchanged,
    /// so fault_ sees only edges, not every fire.
    void collect_health(DirWatch& w, bool faulted,
                        std::vector<std::pair<std::string, bool>>& out) {
        if (w.faulted == faulted)
            return;
        w.faulted = faulted;
        for (auto& [fname, keys] : w.keys)
            for (const auto& k : keys)
                out.emplace_back(k, faulted);
    }

    /// Re-attempt every absent directory watch (an ancestor fired). Any that now
    /// opens re-arms, drops its ancestor dependency, and clears any prior fault.
    void reresolve_absent(std::vector<std::pair<std::string, bool>>& faults) {
        for (auto& [dirkey, slot] : dirs_) {
            if (slot && !slot->handle && !slot->keys.empty() && arm_dir(*slot)) {
                release_ancestor(*slot);
                collect_health(*slot, false, faults); // recovered
            }
        }
    }

    /// Walk the FILE_NOTIFY_INFORMATION records in `bytes` and collect each
    /// spark key whose filename changed (called under mu_; pure — the emit
    /// happens later, lock-released). `bytes == 0` = buffer overflow: we can't
    /// tell which files changed, so fire EVERY key in the dir (never miss one).
    std::vector<std::string> collect_fire(DirWatch& w, DWORD bytes) const {
        std::vector<std::string> fire;
        if (bytes == 0) {
            for (auto& [fname, keys] : w.keys)
                fire.insert(fire.end(), keys.begin(), keys.end());
            return fire;
        }
        std::size_t off = 0;
        for (;;) {
            if (off + offsetof(FILE_NOTIFY_INFORMATION, FileName) > bytes)
                break;
            auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(w.buf + off);
            const std::size_t name_bytes = info->FileNameLength;
            if (off + offsetof(FILE_NOTIFY_INFORMATION, FileName) + name_bytes > bytes)
                break;
            const std::wstring fname =
                fold_ci(std::wstring_view(info->FileName, name_bytes / sizeof(WCHAR)));
            auto fi = w.keys.find(fname);
            if (fi != w.keys.end())
                fire.insert(fire.end(), fi->second.begin(), fi->second.end());
            if (info->NextEntryOffset == 0)
                break;
            off += info->NextEntryOffset;
        }
        return fire;
    }

    void run() {
        std::unique_lock lk(mu_);
        while (!stop_.load(std::memory_order_acquire)) {
            lk.unlock();
            DWORD bytes = 0;
            ULONG_PTR ckey = 0;
            LPOVERLAPPED ov = nullptr;
            const BOOL ok =
                ::GetQueuedCompletionStatus(iocp_.get(), &bytes, &ckey, &ov, INFINITE);
            lk.lock();
            if (stop_.load(std::memory_order_acquire))
                break;
            if (ckey == kControlKey)
                continue; // control wake (stop / future nudges)

            auto* w = reinterpret_cast<DirWatch*>(ckey);
            const bool is_ancestor = is_ancestor_watch(w);
            w->io_pending = false;

            // Collect fires + health transitions under mu_; dispatch them AFTER
            // releasing it (emit_/fault_ re-enter the engine under its lock, and
            // an inline consumer may re-arm → back into watch()/mu_).
            std::vector<std::string> emits;
            std::vector<std::pair<std::string, bool>> faults;

            if (w->removing) {
                drop_watch(w); // its aborted completion drained — free it now (do NOT touch w after)
            } else if (!ok) {
                // Directory handle went bad (deleted).
                w->handle.reset();
                if (!is_ancestor) {
                    // A real dir with NO ancestor armable is fully deaf → fault (B1).
                    collect_health(*w, !arm_ancestor(*w), faults);
                } else {
                    // UP2-2: the ANCESTOR dir itself was deleted. Left alone, its
                    // dead (handle-null) slot strands every dependent — they only
                    // recover on an ancestor fire this dead handle can never
                    // deliver — and leaks the zombie slot + poisons a later
                    // arm_ancestor that reuses its key. Re-point every dependent to
                    // a fresh (higher) ancestor; arm_ancestor releases the dead one
                    // (refcount→0 → erased; handle already null, so no drain). w may
                    // be freed by that release — copy its key first and don't touch
                    // w afterward.
                    const std::wstring dead_akey = fold_ci(w->dir);
                    for (auto& [dirkey, slot] : dirs_) {
                        if (slot && slot->ancestor_key == dead_akey)
                            collect_health(*slot, !arm_ancestor(*slot), faults);
                    }
                }
            } else if (is_ancestor) {
                // Something under the ancestor changed — a previously-absent
                // parent may now exist. Re-arm the ancestor and re-resolve.
                route_noop_rearm(*w);
                reresolve_absent(faults);
            } else {
                // Re-arm BEFORE processing (the #1907 condition-4 discipline: no
                // dropped-change window). UP-2: if the dir vanished at re-arm, the
                // ignored return used to leave the watch permanently deaf — now
                // fall back to an ancestor watch (matching the !ok branch) and
                // report health so a truly-deaf watch is observable.
                emits = collect_fire(*w, bytes);
                if (!arm_dir(*w))
                    collect_health(*w, !arm_ancestor(*w), faults);
                else
                    collect_health(*w, false, faults); // healthy — clears any prior fault
            }

            if (!emits.empty() || !faults.empty()) {
                SparkEmitFn emit = emit_;
                SparkFaultFn fault = fault_;
                lk.unlock();
                for (const auto& key : emits)
                    if (emit)
                        emit(key, SparkData{std::monostate{}});
                for (const auto& [key, faulted] : faults)
                    if (fault)
                        fault(key, faulted, faulted ? "file re-arm failed" : "recovered");
                lk.lock();
            }
        }
    }

    bool is_ancestor_watch(DirWatch* w) const {
        for (const auto& [k, slot] : ancestors_)
            if (slot.get() == w)
                return true;
        return false;
    }

    void route_noop_rearm(DirWatch& w) {
        // Ancestor watches carry no spark keys — just keep them armed.
        w.io_pending = ::ReadDirectoryChangesW(w.handle.get(), w.buf, sizeof(w.buf), FALSE, kFilter,
                                               nullptr, &w.ov, nullptr) != 0;
    }

    void drop_watch(DirWatch* w) {
        for (auto it = dirs_.begin(); it != dirs_.end(); ++it)
            if (it->second.get() == w) {
                dirs_.erase(it);
                return;
            }
        for (auto it = ancestors_.begin(); it != ancestors_.end(); ++it)
            if (it->second.get() == w) {
                ancestors_.erase(it);
                return;
            }
        for (auto it = retiring_.begin(); it != retiring_.end(); ++it)
            if (it->get() == w) {
                retiring_.erase(it);
                retiring_gauge_.fetch_sub(1, std::memory_order_relaxed);
                return;
            }
    }

    std::mutex mu_;
    detail::EventHandle iocp_; ///< IOCP handle (closed via CloseHandle)
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    std::thread worker_;
    std::atomic<bool> stop_{true};
    std::unordered_map<std::wstring, std::unique_ptr<DirWatch>> dirs_;      ///< real watched dirs
    std::unordered_map<std::wstring, std::unique_ptr<DirWatch>> ancestors_; ///< recreate-recovery
    std::vector<std::unique_ptr<DirWatch>> retiring_; ///< ancestors awaiting a drained completion
    std::unordered_map<std::string, std::pair<std::wstring, std::wstring>> key_index_; ///< key→(dir,fname)

    // #1979 stats (SparkMechanismStats) — atomic, no lock shared with mu_ so
    // stats() never blocks on or contends with watch/unwatch/stop.
    std::atomic<std::uint64_t> retiring_gauge_{0};
    std::atomic<std::uint64_t> watch_rejected_{0};
    std::atomic<std::uint64_t> quarantined_{0};
    std::atomic<std::uint64_t> slow_op_{0}; ///< bumped by PR-E (#1980)
    /// Started, but the IOCP could not be created — every watch() will be refused.
    /// Atomic so stats() (const, heartbeat thread) reads it without mu_.
    std::atomic<bool> inert_{false};
};

} // namespace

std::unique_ptr<ISparkMechanism> make_file_mechanism() {
    return std::make_unique<WindowsFileMechanism>();
}

} // namespace yuzu::agent

#else // ── Non-Windows: file-change spark is Windows-only for the MVP ──────────

namespace yuzu::agent {

std::unique_ptr<ISparkMechanism> make_file_mechanism() {
    return nullptr; // no mechanism → SparkEngine rejects arm(File) off Windows
}

} // namespace yuzu::agent

#endif // _WIN32
