/**
 * guard_launchd.cpp — see guard_launchd.hpp.
 *
 * macOS: one LaunchdWatchCore watch thread owns a kqueue and a poll schedule. Per
 * watched label it runs `launchctl print system/<label>` on a bounded cadence
 * (the primary observe channel — launchd has no public state-change notification
 * API), classifies the result, and re-arms an EVFILT_PROC/NOTE_EXIT kevent on the
 * job's live PID so a stop wakes the thread immediately; the wake only schedules
 * an immediate RE-POLL — the fresh `launchctl print` is what is classified and
 * emitted, never the raw kernel event (KeepAlive may already have respawned the
 * job, and PID reuse means the event alone proves nothing about the label).
 * LaunchdServiceGuard adapts observations onto the GuardDrift sink through
 * launchd_decide_emit (dedup + collapse debounce, the systemd commit rules).
 *
 * v1 is OBSERVE ONLY: enforce-mode rules are detected + reported but NOT
 * remediated (no stable public launchd control API — design §20). Enforcement is
 * a separate, governance-gated change.
 *
 * The pure helpers (parse_launchctl_print / classify / compliance / decide_emit)
 * are compiled on EVERY platform so they are unit-testable off macOS against
 * captured `launchctl print` output (mirrors guard_systemd.cpp). Only the kqueue
 * engine is Apple-gated; off macOS the core is a stub (watch() reports
 * unsupported) and the guard's start() returns false through it.
 */

#include <yuzu/agent/guard_launchd.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::agent {

// ── Pure helpers (compiled on every platform) ─────────────────────────────────

LaunchdJobInfo parse_launchctl_print(std::string_view text) {
    LaunchdJobInfo info;
    int depth = 0;
    std::size_t pos = 0;
    while (pos < text.size()) {
        const std::size_t eol = text.find('\n', pos);
        std::string_view line =
            text.substr(pos, (eol == std::string_view::npos ? text.size() : eol) - pos);
        pos = (eol == std::string_view::npos) ? text.size() : eol + 1;

        const std::size_t begin = line.find_first_not_of(" \t");
        if (begin == std::string_view::npos)
            continue;
        std::string_view t = line.substr(begin);
        if (!t.empty() && t.back() == '\r')
            t.remove_suffix(1);
        if (t.empty())
            continue;

        // Only depth-1 lines are the job's own fields. Nested blocks (arguments /
        // environment / endpoints / coalitions) carry their own `key = value`
        // lines — including `state = active` inside coalition sub-blocks on a
        // NOT-running job — which must never override the top-level fields.
        // A block-opening line (ends with '{') is never a scalar field.
        if (depth == 1 && t.back() != '{') {
            const std::size_t sep = t.find(" = ");
            if (sep != std::string_view::npos) {
                const std::string_view key = t.substr(0, sep);
                const std::string_view val = t.substr(sep + 3);
                if (key == "state") {
                    if (val == "running")
                        info.state = LaunchdState::Running;
                    else if (val == "not running")
                        info.state = LaunchdState::NotRunning;
                    else if (val == "waiting")
                        info.state = LaunchdState::Waiting;
                    else
                        info.state = LaunchdState::Unknown; // unrecognised — held
                } else if (key == "pid") {
                    std::int64_t v = 0;
                    const auto [p, ec] = std::from_chars(val.data(), val.data() + val.size(), v);
                    if (ec == std::errc{} && v > 0)
                        info.pid = v;
                } else if (key == "path") {
                    info.path = std::string(val);
                } else if (key == "program") {
                    info.program = std::string(val);
                }
            }
        }
        // Structural brace tracking: a block OPENS on a line ending with '{'
        // (`arguments = {`, `"label" = {`) and CLOSES on a line that is exactly
        // '}'. Counting brace CHARACTERS instead would let a '{'/'}' inside a
        // job-controlled field value (a program path / argument) corrupt the depth
        // and hide the top-level `state` line (UP-7). Single-line blocks
        // (`resource coalition = { ... }`) end with '}' → match neither rule, net 0.
        if (t.back() == '{')
            ++depth;
        else if (t == "}")
            --depth;
        if (depth < 0)
            depth = 0; // malformed input never underflows the tracker
    }
    return info;
}

LaunchdJobInfo classify_launchctl_print(int exit_code, std::string_view output) {
    LaunchdJobInfo info; // state defaults to Unknown (held)
    // Absence needs BOTH signals: the definitive marker AND a REAL failing exit
    // (exit_code > 0 — WIFEXITED-derived; launchctl reports a genuinely unknown
    // label with the marker + exit 113, observed live). A SUCCESSFUL print whose
    // job-controlled fields happen to contain the marker text must parse
    // normally, or a root-planted string reads a running job as absent
    // (false-compliant for service-stopped — adversarial-review C5). Every other
    // failure — popen failure / signal-killed child (exit_code < 0, even if the
    // partial output carries the marker), a failing exit without the marker,
    // empty output — is transient and must NOT read as absence, or a blip
    // fabricates a false "stopped" drift (the systemd_error_name_is_absence
    // discipline).
    if (exit_code > 0 && output.find("Could not find service") != std::string_view::npos) {
        info.state = LaunchdState::Absent;
        return info;
    }
    if (exit_code != 0 || output.empty())
        return info;
    return parse_launchctl_print(output);
}

bool launchd_state_is_transitional(LaunchdState s) {
    // launchctl print exposes no mid-transition vocabulary: running / not running
    // / waiting / absent are all terminal. Only a state we do not understand (or a
    // transient query failure) is held, so it can never raise a false positive.
    return s == LaunchdState::Unknown;
}

bool launchd_is_compliant(ServiceGuard::Desired want, LaunchdState got) {
    if (want == ServiceGuard::Desired::Running)
        return got == LaunchdState::Running;
    // Desired::Stopped — anything not executing counts as stopped; an idle
    // on-demand job or a missing label is, definitionally, not running.
    return got == LaunchdState::NotRunning || got == LaunchdState::Waiting ||
           got == LaunchdState::Absent;
}

std::string_view launchd_state_token(LaunchdState s) {
    switch (s) {
    case LaunchdState::Running:    return "running";
    case LaunchdState::NotRunning: return "stopped";
    case LaunchdState::Waiting:    return "waiting";
    case LaunchdState::Absent:     return "absent";
    case LaunchdState::Unknown:    return "unknown";
    }
    return "unknown";
}

bool valid_launchd_label(std::string_view label) {
    if (label.empty() || label.size() > 256)
        return false;
    for (char c : label) {
        const auto uc = static_cast<unsigned char>(c);
        if (!std::isalnum(uc) && c != '.' && c != '_' && c != '-' && c != '@')
            return false;
    }
    return true;
}

EmitDecision launchd_decide_emit(ServiceGuard::Desired want, LaunchdState got,
                                 LaunchdEmitState& state, std::uint64_t debounce_ms,
                                 std::chrono::steady_clock::time_point now) {
    if (launchd_state_is_transitional(got))
        return {EmitAction::Hold, 0}; // not understood — never commit
    if (got == state.last_terminal)
        return {EmitAction::NoChange, 0}; // already committed this terminal state
    if (launchd_is_compliant(want, got)) {
        // Compliant edge: commit so a LATER drift back to a previously-drifted
        // state reads as a real change (re-drift-after-recovery). Drift-only sink
        // → silent.
        state.last_terminal = got;
        return {EmitAction::CompliantSilent, 0};
    }
    // Non-compliant terminal change → a drift, subject to the collapse debounce.
    if (state.last_emit && (now - *state.last_emit) < std::chrono::milliseconds(debounce_ms)) {
        // Fold into the count but do NOT commit last_terminal — leaving it
        // uncommitted lets this drift re-surface at the next poll instead of
        // being deduped away if the job settles back into this same state.
        ++state.suppressed;
        return {EmitAction::Suppressed, 0};
    }
    state.last_terminal = got; // commit on emit
    const std::uint64_t collapsed = state.suppressed;
    state.suppressed = 0;
    state.last_emit = now;
    return {EmitAction::Emit, collapsed};
}

// ── LaunchdServiceGuard (compiled on every platform — the core stubs off macOS) ──

LaunchdServiceGuard::LaunchdServiceGuard(Config cfg, Sink sink)
    : cfg_(std::move(cfg)), sink_(std::move(sink)) {}

LaunchdServiceGuard::~LaunchdServiceGuard() { stop(); }

bool LaunchdServiceGuard::start() {
    if (!valid_launchd_label(cfg_.service_name)) {
        spdlog::warn("Guardian LaunchdServiceGuard[{}]: invalid launchd label '{}'", cfg_.rule_id,
                     cfg_.service_name);
        return false;
    }
    core_.start([this](const LaunchdWatchEvent& ev) { on_observation(ev.info); },
                [this](const std::string& /*key*/, const std::string& why) {
                    spdlog::warn("Guardian LaunchdServiceGuard[{}]: watch fault on job '{}': {}",
                                 cfg_.rule_id, cfg_.service_name, why);
                });
    if (auto armed = core_.watch(cfg_.rule_id, cfg_.service_name); !armed) {
        spdlog::warn("Guardian LaunchdServiceGuard[{}]: could not watch job '{}': {}", cfg_.rule_id,
                     cfg_.service_name, armed.error());
        core_.stop();
        return false;
    }
    if (cfg_.enforce)
        spdlog::warn("Guardian LaunchdServiceGuard[{}]: enforce-mode not yet supported on macOS — "
                     "observing job '{}' only (drift reported, not remediated)",
                     cfg_.rule_id, cfg_.service_name);
    spdlog::info("Guardian LaunchdServiceGuard[{}]: watching job '{}' (expect {})", cfg_.rule_id,
                 cfg_.service_name, cfg_.desired == Desired::Running ? "running" : "stopped");
    return true;
}

void LaunchdServiceGuard::stop() { core_.stop(); }

void LaunchdServiceGuard::on_observation(const LaunchdJobInfo& info) {
    const EmitDecision d = launchd_decide_emit(cfg_.desired, info.state, emit_state_,
                                               cfg_.event_debounce_ms,
                                               std::chrono::steady_clock::now());
    if (d.action != EmitAction::Emit)
        return;
    ServiceDrift drift;
    drift.guard_type = "service";
    drift.rule_id = cfg_.rule_id;
    drift.rule_name = cfg_.rule_name;
    drift.detected_value = std::string(launchd_state_token(info.state));
    drift.expected_value = (cfg_.desired == Desired::Running) ? "running" : "stopped";
    drift.detection_latency_us = 0; // v1: not measured (neither poll nor kqueue carries event time)
    drift.collapsed_count = d.collapsed_count;
    spdlog::info("Guardian LaunchdServiceGuard[{}]: drift job '{}' detected={} expected={}",
                 cfg_.rule_id, cfg_.service_name, drift.detected_value, drift.expected_value);
    if (sink_)
        sink_(drift);
}

} // namespace yuzu::agent

#if defined(__APPLE__) // ── kqueue + launchctl poll engine ─────────────────────

#include <sys/event.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace yuzu::agent {
namespace {

constexpr std::uintptr_t kStopIdent = 1; // EVFILT_USER — wakes run() (stop or new watch)
// The primary observe cadence (design §19.2.3's 30s state poll). The kqueue
// NOTE_EXIT overlay carries the fast path for stops; the poll bounds start /
// reload / absent-return detection and is the correctness backstop when
// EVFILT_PROC could not be armed.
constexpr std::uint64_t kPollIntervalMs = 30000;
constexpr long long kMaxIdleWaitMs = 60000; // kevent timeout cap while no deadline is near

struct LaunchctlResult {
    int exit_code{-1}; // -1 = popen/pclose failure or abnormal termination (transient)
    std::string output;
};

// RAII pipe that surfaces pclose's status — dex_macos's PipeHandle discards it,
// and the exit code is load-bearing here (absent vs transient). pclose runs on
// every exit path, including a bad_alloc thrown by the read loop (Governance B1:
// a manual pclose with a throwing statement in between leaks the pipe and lets
// the exception escape the worker thread → std::terminate).
class StatusPipe {
public:
    explicit StatusPipe(const char* cmd) : f_(::popen(cmd, "r")) {}
    ~StatusPipe() { (void)close(); }
    StatusPipe(const StatusPipe&) = delete;
    StatusPipe& operator=(const StatusPipe&) = delete;
    FILE* get() const { return f_; }
    int close() {
        if (!f_)
            return rc_;
        rc_ = ::pclose(f_);
        f_ = nullptr;
        return rc_;
    }

private:
    FILE* f_{nullptr};
    int rc_{-1};
};

LaunchctlResult run_launchctl_print(const std::string& label) {
    // Documented shell-unavoidable exception (cpp-conventions, new-popen rule):
    // the shell is used deliberately for the `2>&1` merge — launchctl reports
    // absence ("Could not find service") on stderr, and popen exposes stdout
    // only. `label` is charset-validated (valid_launchd_label) at BOTH the guard
    // and watch() layers — the injection gate for this interpolation. No timeout
    // wrapper: macOS ships no /usr/bin/timeout, and a hung `launchctl print`
    // means launchd itself is wedged (host-dead territory) — the established
    // posture of every launchctl call site in the tree.
    LaunchctlResult res;
    if (!valid_launchd_label(label)) // belt-and-suspenders: never reachable via the
        return res;                  // validated callers; guards any future call site
    const std::string cmd = "/bin/launchctl print system/" + label + " 2>&1";
    StatusPipe pipe(cmd.c_str());
    if (!pipe.get())
        return res;
    // Bound the buffer: one job's `print` is a few KB, but capping keeps a
    // pathological/hostile output from growing the string without limit (the
    // first ~64 KiB carry `state`/`pid` — all this parser reads). Drain the rest
    // so pclose still reaps a clean child.
    constexpr std::size_t kMaxOutput = 64 * 1024;
    char buf[4096];
    while (std::fgets(buf, sizeof(buf), pipe.get()))
        if (res.output.size() < kMaxOutput)
            res.output += buf;
    const int rc = pipe.close();
    if (rc != -1 && WIFEXITED(rc))
        res.exit_code = WEXITSTATUS(rc);
    return res;
}

} // namespace

struct LaunchdWatchCore::Impl {
    struct Watch {
        std::string label;
        std::chrono::steady_clock::time_point next_poll; // due when <= now
        std::int64_t armed_pid{0};         // EVFILT_PROC-registered PID (0 = none)
        bool format_unknown_warned{false}; // deduped "output did not classify" warn
    };

    std::mutex mu; // guards watches / flags / kq lifecycle (control plane + thread)
    std::unordered_map<std::string, Watch> watches;
    LaunchdWatchEmitFn emit;
    LaunchdWatchFaultFn fault;
    int kq{-1};
    std::thread thread;
    std::atomic<bool> running{false};
    bool started{false}; // start() ran (successfully or not)
    bool usable{false};  // kqueue + stop-wake armed, thread live

    void wake() {
        std::lock_guard lk(mu);
        if (kq < 0)
            return;
        struct kevent w{};
        EV_SET(&w, kStopIdent, EVFILT_USER, 0, NOTE_TRIGGER, 0, nullptr);
        (void)::kevent(kq, &w, 1, nullptr, 0, nullptr);
    }

    // Under mu. True when a DIFFERENT watch still relies on the same pid's
    // EVFILT_PROC registration — knotes key on (kq, ident, filter), so an
    // EV_DELETE on behalf of one watch would strand every sibling's fast-stop
    // path (the Stage-2 multiplex surface; on_pid_exit already scans siblings).
    bool pid_armed_elsewhere(const Watch* self, std::int64_t pid) const {
        for (const auto& [key, w] : watches)
            if (&w != self && w.armed_pid == pid)
                return true;
        return false;
    }

    // Under mu. Keep the NOTE_EXIT registration in step with the job's live PID.
    // An arm failure (EPERM on a foreign PID without privilege, or ESRCH when the
    // process died between print and arm) degrades that watch to poll-only —
    // stop-detection latency goes from ~0ms to the poll cadence, correctness is
    // unaffected.
    void rearm_proc_watch(Watch& w, const LaunchdJobInfo& info) {
        const std::int64_t want_pid =
            (info.state == LaunchdState::Running && info.pid) ? *info.pid : 0;
        if (want_pid == w.armed_pid)
            return;
        if (w.armed_pid != 0) {
            if (!pid_armed_elsewhere(&w, w.armed_pid)) {
                struct kevent del{};
                EV_SET(&del, static_cast<std::uintptr_t>(w.armed_pid), EVFILT_PROC, EV_DELETE, 0, 0,
                       nullptr);
                (void)::kevent(kq, &del, 1, nullptr, 0, nullptr); // kernel may have dropped it
            }
            w.armed_pid = 0;
        }
        if (want_pid != 0) {
            // INVARIANT (PID-reuse safety): a knote is armed ONLY for the pid of a
            // job we currently classify Running. NOTE_EXIT then only ever schedules
            // a re-poll (on_pid_exit) that reclassifies against the LABEL — so a
            // reused pid or a KeepAlive respawn yields a correct fresh read, never a
            // state inferred from the raw event. Do not add a path that emits off the
            // kernel event, or PID reuse becomes a false-state source.
            struct kevent add{};
            EV_SET(&add, static_cast<std::uintptr_t>(want_pid), EVFILT_PROC, EV_ADD | EV_CLEAR,
                   NOTE_EXIT, 0, nullptr);
            if (::kevent(kq, &add, 1, nullptr, 0, nullptr) == 0)
                w.armed_pid = want_pid;
            else
                spdlog::debug("Guardian LaunchdWatchCore: EVFILT_PROC arm failed for pid {} "
                              "(errno={}) — poll-only for '{}'",
                              want_pid, errno, w.label);
        }
    }

    // A watched job's process exited: clear the bookkeeping and schedule an
    // IMMEDIATE re-poll — the fresh launchctl print is what gets classified;
    // never emit straight off the kernel event (KeepAlive respawn / PID reuse).
    void on_pid_exit(std::int64_t pid) {
        std::lock_guard lk(mu);
        struct kevent del{};
        EV_SET(&del, static_cast<std::uintptr_t>(pid), EVFILT_PROC, EV_DELETE, 0, 0, nullptr);
        (void)::kevent(kq, &del, 1, nullptr, 0, nullptr); // best-effort tidy
        const auto now = std::chrono::steady_clock::now();
        for (auto& [key, w] : watches) {
            if (w.armed_pid == pid) {
                w.armed_pid = 0;
                w.next_poll = now;
            }
        }
    }

    void poll_due() {
        // Snapshot due watches under the lock; run the (slow) subprocess outside
        // it so watch/unwatch are never blocked behind launchctl.
        std::vector<std::pair<std::string, std::string>> due; // key, label
        {
            std::lock_guard lk(mu);
            const auto now = std::chrono::steady_clock::now();
            for (auto& [key, w] : watches)
                if (w.next_poll <= now)
                    due.emplace_back(key, w.label);
        }
        for (auto& [key, label] : due) {
            const LaunchctlResult res = run_launchctl_print(label);
            const LaunchdJobInfo info = classify_launchctl_print(res.exit_code, res.output);
            LaunchdWatchEmitFn emit_copy;
            {
                std::lock_guard lk(mu);
                auto it = watches.find(key);
                if (it == watches.end() || it->second.label != label)
                    continue; // unwatched while we polled — drop the stale result
                it->second.next_poll = std::chrono::steady_clock::now() +
                                       std::chrono::milliseconds(kPollIntervalMs);
                // Observability for silent format drift: a clean exit with output
                // we could not classify (state Unknown) means launchctl's output
                // shape changed under us (an OS update) — the guard then HOLDS
                // forever with no other signal. Warn once per watch; reset when it
                // parses again. (Distinguishable from transient failure only here,
                // where the exit code + output are both in hand.)
                const bool unparsed = res.exit_code == 0 && !res.output.empty() &&
                                      info.state == LaunchdState::Unknown;
                if (unparsed && !it->second.format_unknown_warned) {
                    spdlog::warn("Guardian LaunchdWatchCore: job '{}' printed output that did not "
                                 "classify (launchctl format drift?) — holding, no drift reported",
                                 label);
                    it->second.format_unknown_warned = true;
                } else if (!unparsed) {
                    it->second.format_unknown_warned = false;
                }
                rearm_proc_watch(it->second, info);
                emit_copy = emit;
            }
            if (emit_copy)
                emit_copy(LaunchdWatchEvent{key, info});
        }
    }

    long long ms_until_next_deadline() {
        std::lock_guard lk(mu);
        const auto now = std::chrono::steady_clock::now();
        long long best = kMaxIdleWaitMs;
        for (auto& [key, w] : watches) {
            const long long d =
                std::chrono::duration_cast<std::chrono::milliseconds>(w.next_poll - now).count();
            best = std::min(best, std::max(0ll, d));
        }
        return best;
    }

    void run() try {
        // Clear `running` on EVERY exit — normal, kevent-failure, OR an escaping
        // exception (function-try unwinds this local before the handler runs). A
        // watch() after the thread has terminally died then fails its running-gate
        // instead of reporting a dead core as armed (cpp-safety: zombie-core false
        // success). Safe against stop(): its exchange(false) returning false just
        // skips the wake; the join still runs on the already-returned thread.
        struct ClearRunning {
            std::atomic<bool>& r;
            ~ClearRunning() { r.store(false, std::memory_order_release); }
        } clear_running{running};
        while (running.load(std::memory_order_acquire)) {
            poll_due();

            const long long wait_ms = ms_until_next_deadline();
            struct timespec ts{};
            ts.tv_sec = wait_ms / 1000;
            ts.tv_nsec = (wait_ms % 1000) * 1000000;
            struct kevent ev{};
            const int n = ::kevent(kq, nullptr, 0, &ev, 1, &ts);
            if (!running.load(std::memory_order_acquire))
                break;
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                spdlog::warn("Guardian LaunchdWatchCore: kevent wait failed (errno={}) — watch "
                             "thread stopping",
                             errno);
                fault_all("kevent wait failed — launchd watch stopped");
                break;
            }
            if (n == 0)
                continue; // deadline — top of loop polls the due watches
            if (ev.filter == EVFILT_USER && ev.ident == kStopIdent)
                continue; // stop (loop condition breaks) or a new watch to poll
            if (ev.filter == EVFILT_PROC && (ev.fflags & NOTE_EXIT))
                on_pid_exit(static_cast<std::int64_t>(ev.ident));
        }
    } catch (const std::exception& e) {
        spdlog::error("Guardian LaunchdWatchCore: watch thread exception: {} — stopping", e.what());
        fault_all(std::string("launchd watch thread exception: ") + e.what());
    } catch (...) {
        spdlog::error("Guardian LaunchdWatchCore: watch thread unknown exception — stopping");
        fault_all("launchd watch thread unknown exception");
    }

    void fault_all(const std::string& why) {
        LaunchdWatchFaultFn fault_copy;
        std::vector<std::string> keys;
        {
            std::lock_guard lk(mu);
            fault_copy = fault;
            keys.reserve(watches.size());
            for (const auto& [k, w] : watches)
                keys.push_back(k);
        }
        if (fault_copy)
            for (const auto& k : keys)
                fault_copy(k, why);
    }
};

LaunchdWatchCore::LaunchdWatchCore() : impl_(std::make_unique<Impl>()) {}

LaunchdWatchCore::~LaunchdWatchCore() { stop(); }

void LaunchdWatchCore::start(LaunchdWatchEmitFn emit, LaunchdWatchFaultFn fault) {
    Impl* im = impl_.get();
    std::lock_guard lk(im->mu);
    if (im->started)
        return;
    im->started = true;
    im->emit = std::move(emit);
    im->fault = std::move(fault);
    im->kq = ::kqueue();
    if (im->kq < 0) {
        spdlog::warn("Guardian LaunchdWatchCore: kqueue() failed (errno={}) — core unusable",
                     errno);
        return;
    }
    // The EVFILT_USER stop filter is load-bearing for clean shutdown: if its
    // registration fails, stop()'s NOTE_TRIGGER is a no-op and join() hangs
    // forever (the dex_macos cs-S1 rule). Treat a registration error as fatal to
    // arming — no thread is spawned that could not be stopped.
    struct kevent ctl{};
    EV_SET(&ctl, kStopIdent, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, nullptr);
    if (::kevent(im->kq, &ctl, 1, nullptr, 0, nullptr) < 0) {
        spdlog::warn("Guardian LaunchdWatchCore: cannot register stop kevent (errno={}) — core "
                     "unusable (clean shutdown could not be guaranteed)",
                     errno);
        ::close(im->kq);
        im->kq = -1;
        return;
    }
    im->running.store(true, std::memory_order_release);
    im->thread = std::thread([im] { im->run(); });
    im->usable = true;
}

std::expected<void, std::string> LaunchdWatchCore::watch(const std::string& key,
                                                         const std::string& label) {
    if (!valid_launchd_label(label))
        return std::unexpected("invalid launchd label (charset/length)");
    Impl* im = impl_.get();
    {
        std::lock_guard lk(im->mu);
        // `running` too, not just `usable`: the core is one-shot, and stop()
        // clears `usable` only after the join — without this gate a concurrent
        // watch() could "succeed" against a thread that is already gone.
        if (!im->usable || !im->running.load(std::memory_order_acquire))
            return std::unexpected("launchd watch core is not running (unarmed or stopped)");
        const auto [it, inserted] = im->watches.try_emplace(
            key, Impl::Watch{label, std::chrono::steady_clock::now(), 0});
        if (!inserted)
            return std::unexpected("duplicate watch key");
    }
    im->wake(); // the initial compare runs promptly on the watch thread
    return {};
}

void LaunchdWatchCore::unwatch(const std::string& key) {
    Impl* im = impl_.get();
    std::lock_guard lk(im->mu);
    const auto it = im->watches.find(key);
    if (it == im->watches.end())
        return;
    if (it->second.armed_pid != 0 && im->kq >= 0 &&
        !im->pid_armed_elsewhere(&it->second, it->second.armed_pid)) {
        struct kevent del{};
        EV_SET(&del, static_cast<std::uintptr_t>(it->second.armed_pid), EVFILT_PROC, EV_DELETE, 0,
               0, nullptr);
        (void)::kevent(im->kq, &del, 1, nullptr, 0, nullptr);
    }
    im->watches.erase(it);
}

void LaunchdWatchCore::stop() {
    Impl* im = impl_.get();
    {
        std::lock_guard lk(im->mu);
        if (!im->started)
            return;
    }
    if (im->running.exchange(false, std::memory_order_acq_rel))
        im->wake();
    if (im->thread.joinable())
        im->thread.join(); // no emit can outlive this join
    std::lock_guard lk(im->mu);
    if (im->kq >= 0) {
        ::close(im->kq);
        im->kq = -1;
    }
    im->watches.clear();
    im->usable = false;
}

} // namespace yuzu::agent

#else // ── Non-macOS: stub so callers and tests build everywhere (dex_macos convention) ──

namespace yuzu::agent {

struct LaunchdWatchCore::Impl {};

LaunchdWatchCore::LaunchdWatchCore() : impl_(std::make_unique<Impl>()) {}
LaunchdWatchCore::~LaunchdWatchCore() { stop(); }
void LaunchdWatchCore::start(LaunchdWatchEmitFn, LaunchdWatchFaultFn) {}
std::expected<void, std::string> LaunchdWatchCore::watch(const std::string&, const std::string&) {
    return std::unexpected("LaunchdWatchCore is only available on macOS");
}
void LaunchdWatchCore::unwatch(const std::string&) {}
void LaunchdWatchCore::stop() {}

} // namespace yuzu::agent

#endif
