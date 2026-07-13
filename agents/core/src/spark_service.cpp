/**
 * spark_service.cpp — the Service spark mechanism (ADR-0021 Stage 1 PR 1c).
 *
 * Third and last event-driven mechanism, completing Stage 1's detection triad
 * (File/IOCP + Registry/TP_WAIT from PR 1b). Multiplexes N systemd-unit /
 * Windows-service run-state watches onto ONE sd-bus connection + ONE thread
 * (Linux) or ONE alertable-wait thread + ONE SCM connection (Windows) —
 * O(mechanism) resources, never O(rules). This is a REWRITE of the per-unit
 * guard_systemd.cpp / guard_service.cpp watch loops (those stay Guardian's;
 * this is the Spark layer), reusing their PURE state-mapping/validation
 * helpers and error-classification rules but replacing "one thread + one
 * connection per watch" with a single poll-thread-confined mechanism.
 *
 * PORTS THE WATCH, NOT THE ASSERTION: a fired spark carries the resolved
 * terminal ServiceRunState (see spark.hpp — Service is the one event-driven
 * type that DOES carry a payload, unlike File/Registry's monostate) but does
 * NO compare-to-desired, NO enforce. That is Guardian's, Stage 2.
 *
 * Resource contract (the acceptance bar, stricter than 1b — thread count alone
 * over-reports the collapse):
 *   Linux:   1 sd_bus connection (1 fd) + 1 eventfd + 1 thread, for ANY N.
 *   Windows: 1 thread + 1 SCM handle + 1 wake event + N service handles
 *            (unavoidable — NotifyServiceStatusChangeW needs one per service).
 *
 * Command marshaling (both platforms) is FIRE-AND-FORGET, not a synchronous
 * handshake: watch()/unwatch() enqueue a command and wake the mechanism
 * thread; they never block waiting for the thread to act on it. This is
 * deliberate, not merely convenient — the emit_/fault_ callbacks run ON the
 * mechanism thread (sd-bus process loop / SCM APC), and an INLINE consumer's
 * handler is allowed to call arm() from inside its own delivery, which calls
 * back into watch() — on the SAME thread that would have to service a
 * handshake. A synchronous wait-for-ack design would self-deadlock (or
 * spuriously time out) on every inline re-arm. There is also nothing genuine
 * to wait for: an absent unit/service is not an arm failure (arm succeeds,
 * the mechanism polls for its return — the guards' own precedent), and every
 * later failure surfaces through the fault channel, not a watch() return.
 *
 * Off macOS and off a Linux build without libsystemd (`systemd_guard` meson
 * option) the factory returns nullptr → SparkEngine rejects arm(Service),
 * preserving "armed == a watcher is running".
 */

#include "spark_mechanism.hpp"

#include <yuzu/agent/guard_systemd.hpp> // parse_active_state, systemd_error_name_is_absence,
                                        // systemd_state_is_transitional, normalize_unit_name,
                                        // valid_unit_name — pure, all-platform, shared with the guard

#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)

// ═══════════════════════════════════════════════════════════════════════════
// Linux: one sd-bus connection + one poll thread, multiplexing N unit watches.
// ═══════════════════════════════════════════════════════════════════════════

#include <systemd/sd-bus.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>      // free
#include <ctime>        // clock_gettime
#include <system_error> // std::generic_category — thread-safe strerror replacement

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace yuzu::agent {
namespace {

constexpr const char* kDest       = "org.freedesktop.systemd1";
constexpr const char* kMgrPath    = "/org/freedesktop/systemd1";
constexpr const char* kMgrIface   = "org.freedesktop.systemd1.Manager";
constexpr const char* kUnitIface  = "org.freedesktop.systemd1.Unit";
constexpr const char* kPropsIface = "org.freedesktop.DBus.Properties";

// Degraded re-poll cadence for an absent/unresolved unit; healthy-watch backstop
// reconcile cadence otherwise. Mirrors guard_systemd.cpp's identical constants —
// the event-driven path is fully push-based while healthy; these are only the
// bounded safety net against a missed signal or a genuinely dead connection.
constexpr std::uint64_t kAbsentRetryMs = 30000;
constexpr std::uint64_t kHealthyReconcileMs = 60000;

std::string err_str(int e) { return std::generic_category().message(e); }

std::uint64_t monotonic_us() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000ull +
           static_cast<std::uint64_t>(ts.tv_nsec) / 1000ull;
}

// Outcome of LoadUnit — mirrors guard_systemd.cpp's ResolveResult split so a
// transient bus error never fabricates a false "stopped" (UP-4 class).
enum class ResolveResult { Resolved, NotFound, BusError };

ServiceRunState map_terminal(SystemdState st) {
    // Only reached for a non-transitional state (caller gates on
    // systemd_state_is_transitional first). Active -> Running; every other
    // terminal value (Inactive/Failed/Absent) -> Stopped, per spark.hpp's
    // documented mapping.
    return st == SystemdState::Active ? ServiceRunState::Running : ServiceRunState::Stopped;
}

// PropertiesChanged match callback. Runs synchronously inside sd_bus_process()
// on the poll thread (never concurrently with the rest of the loop), so it
// just flags the unit dirty — the loop re-reads ActiveState rather than
// parsing the changed-property set, which is both simpler and robust to
// PropertiesChanged batching (mirrors guard_systemd.cpp's on_props_changed).
struct UnitWatch;
int on_props_changed(sd_bus_message*, void* userdata, sd_bus_error*);

struct PendingEmit {
    std::string key;
    ServiceRunState state;
};
struct PendingFault {
    std::string key;
    bool faulted;
    std::string reason;
};

/// One watched systemd unit, poll-thread-confined (no lock — see the class
/// comment on LinuxServiceMechanism). Distinct spark keys ("ssh" vs
/// "ssh.service") may coalesce onto the same UnitWatch; a fire fans out to
/// every key in `keys`.
struct UnitWatch {
    std::string unit; ///< normalized name (normalize_unit_name); map key in units_
    std::set<std::string> keys;
    std::string path; ///< resolved object path; empty = absent/unresolved
    std::unique_ptr<sd_bus_slot, decltype(&sd_bus_slot_unref)> slot{nullptr, &sd_bus_slot_unref};
    bool dirty{false};
    std::optional<ServiceRunState> last; ///< edge-dedup baseline; nullopt until the first terminal
    bool faulted{false};
    std::chrono::steady_clock::time_point next_backstop{};
};

int on_props_changed(sd_bus_message*, void* userdata, sd_bus_error*) {
    if (userdata)
        static_cast<UnitWatch*>(userdata)->dirty = true;
    return 0;
}

/// Linux Service spark mechanism: ONE sd-bus connection + ONE poll thread
/// service every armed unit watch. `watch()`/`unwatch()` (called from
/// engine/consumer threads) never touch the bus directly — sd-bus handles are
/// strictly single-thread-confined, so they enqueue a command under `mu_` and
/// wake the poll thread via an eventfd. `mu_` protects ONLY `pending_` and the
/// start/stop flags; `units_` and all per-unit state are poll-thread-confined
/// (stronger than spark_registry.cpp's collect-under-lock/dispatch-released —
/// here there is nothing to collect a lock for, so emit_/fault_ are trivially
/// never invoked under any lock).
class LinuxServiceMechanism final : public ISparkMechanism {
public:
    ~LinuxServiceMechanism() override { stop(); }

    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        // teardown_mu_ before mu_ (see the member note). start() must exclude stop(), not
        // just stop-vs-stop: start() assigns thread_/bus_/wake_fd_ while stop() joins the
        // thread and frees those same members holding only teardown_mu_. Without this the
        // mechanism would still be relying on SparkEngine::lifecycle_mu_ to keep them
        // apart — and ISparkMechanism is a public interface that must not depend on a
        // caller's lock. (Gate-8 round 2 cpp-safety.)
        std::lock_guard teardown(teardown_mu_);
        std::lock_guard lk(mu_);
        if (started_)
            return; // idempotent
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        sd_bus* bus = nullptr;
        int r = sd_bus_open_system(&bus);
        if (r < 0 || !bus) {
            spdlog::warn("spark_service: system bus unavailable ({}) — service sparks inert on "
                         "this host (non-systemd host?)",
                         r < 0 ? err_str(-r) : std::string("no bus"));
            if (bus)
                sd_bus_unref(bus);
            inert_ = true;
            started_ = true; // "started" so watch() reaches the inert_ rejection, not "not started"
            return;
        }
        int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (efd < 0) {
            sd_bus_unref(bus);
            inert_ = true;
            started_ = true;
            return;
        }
        bus_ = bus;
        wake_fd_ = efd;
        stop_.store(false, std::memory_order_release);
        thread_ = std::thread([this] { run(); });
        started_ = true;
    }

    std::expected<void, std::string> watch(const std::string& key,
                                           const SparkParams& params) override {
        const auto* sp = std::get_if<ServiceSparkParams>(&params);
        if (!sp)
            return std::unexpected("service mechanism: params are not ServiceSparkParams");
        // Defence-in-depth parity with the Windows mechanism's valid_service_name
        // check (governance Gate-2 finding): production arms are already gated
        // by the engine's valid_unit_name call in validate_and_floor, but this
        // watch() is directly callable in tests, bypassing the engine.
        if (!valid_unit_name(sp->service_name))
            return std::unexpected("service mechanism: invalid unit name '" + sp->service_name +
                                   "'");
        std::lock_guard lk(mu_);
        if (!started_)
            return std::unexpected("service mechanism not started");
        if (inert_)
            return std::unexpected("system bus unavailable — service sparks unsupported on this "
                                   "host");
        pending_.push_back(Cmd{Cmd::Add, key, normalize_unit_name(sp->service_name)});
        wake();
        return {};
    }

    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        if (!started_ || inert_)
            return;
        pending_.push_back(Cmd{Cmd::Remove, key, {}});
        wake();
    }

    void stop() override {
        // CLAIM the resources under mu_, in one atomic step: move them into locals and
        // null the members. Whoever wins the lock owns the teardown; every later caller
        // finds a cleared object and returns.
        //
        // Guarding on the RESOURCES rather than on started_ is what fixes the original
        // leak: start() publishes bus_/wake_fd_ BEFORE spawning the poll thread, and the
        // std::thread ctor throws std::system_error under EAGAIN — the very
        // thread-exhaustion case agent.cpp's degrade-to-no-spark guard exists to survive.
        // started_ is never reached on that throw, so a bool-only guard early-returned
        // here and leaked the sd_bus connection AND the eventfd for the process lifetime
        // (~this calls the same stop(), so it could not recover either). bus_/wake_fd_ are
        // RAW members (void*/int) — unlike the Windows SCM twin below, whose scm_/wake_
        // are RAII handles that self-release even on an early return, and unlike
        // spark_file.cpp (guards on iocp_) / spark_registry.cpp (guards on pool_), which
        // already guard on the resource. This mechanism was the only one that could leak.
        //
        // But a resource guard that READS the members while they are only cleared LATE,
        // outside the lock, is merely SEQUENTIALLY idempotent: two concurrent stop()s
        // would both see a live bus_ and both fall through — double sd_bus_unref, double
        // close(), double join. The old !started_ guard was concurrency-safe precisely
        // because started_ flipped under mu_. SparkEngine::lifecycle_mu_ happens to
        // serialise stop() today, but ISparkMechanism::stop() is a public interface
        // documented as idempotent and must not depend on a caller's lock. Claiming under
        // mu_ restores that. (Gate-8 cpp-safety — a regression in the B1 fix itself.)
        // teardown_mu_ serialises stop() END TO END — the same shape as
        // SparkEngine::lifecycle_mu_, one level down. A second caller (the destructor, or
        // a concurrent engine stop()) BLOCKS here until the first has finished, then finds
        // a fully-cleared object and early-returns below. That is what makes the resource
        // guard safe under concurrency without touching the resources early.
        //
        // Do NOT be tempted to "claim" bus_/wake_fd_ into locals under mu_ instead: the
        // poll thread READS wake_fd_ in run() for as long as it is alive, so nulling the
        // members before the join is a data race (TSan caught exactly that). The
        // resources may only be released AFTER the thread has joined — which is precisely
        // why the original code cleared them late, and why the fix belongs in a teardown
        // lock rather than in an earlier claim.
        std::lock_guard teardown(teardown_mu_);
        {
            std::lock_guard lk(mu_);
            if (!started_ && !bus_ && wake_fd_ < 0 && !thread_.joinable())
                return; // nothing was ever acquired, or a previous stop() already cleared it
            started_ = false;
        }
        if (thread_.joinable()) {
            stop_.store(true, std::memory_order_release);
            wake();
            thread_.join();
        }
        // The poll thread has joined — units_/bus_/wake_fd_ are now safe to touch without
        // a lock, and nothing can be reading them. Clearing units_ runs every UnitWatch's
        // slot RAII (unref) BEFORE the bus itself is unref'd below (a slot holds a ref on
        // the bus it matched against — the same ordering guard_systemd.cpp's reopen_bus
        // enforces).
        units_.clear();
        key_unit_.clear();
        if (bus_) {
            sd_bus_flush(static_cast<sd_bus*>(bus_));
            sd_bus_unref(static_cast<sd_bus*>(bus_));
            bus_ = nullptr;
        }
        if (wake_fd_ >= 0) {
            ::close(wake_fd_);
            wake_fd_ = -1;
        }
        std::lock_guard lk(mu_);
        emit_ = nullptr;
        fault_ = nullptr;
        inert_ = false;
        pending_.clear();
    }

    /// This mechanism tracks none of the File-mechanism counters (retiring/quarantine/
    /// slow-op are ReadDirectoryChangesW-specific — #1979/#1980/#1982); its own
    /// fault-tiering and retry counters are tracked separately (#1929/#1931). What it
    /// MUST publish is `inert`, so the fleet can tell a service mechanism that bound
    /// the system bus from one that never did (the container case).
    [[nodiscard]] SparkMechanismStats stats() const override {
        return {.inert = inert_.load(std::memory_order_acquire)};
    }

private:
    struct Cmd {
        enum Op { Add, Remove } op;
        std::string key;
        std::string unit; // only meaningful for Add
    };

    void wake() {
        if (wake_fd_ < 0)
            return;
        const std::uint64_t one = 1;
        ssize_t w = ::write(wake_fd_, &one, sizeof(one));
        (void)w; // best-effort; the poll thread also re-checks pending_/stop_ each loop
    }

    // ── Poll-thread-confined helpers (called only from run()) ──────────────

    ResolveResult resolve_path(sd_bus* bus, UnitWatch& uw) {
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_message* reply = nullptr;
        ResolveResult res = ResolveResult::BusError; // fail-safe default (cpp-safety Gate-8)
        int r = sd_bus_call_method(bus, kDest, kMgrPath, kMgrIface, "LoadUnit", &err, &reply, "s",
                                   uw.unit.c_str());
        if (r >= 0 && reply) {
            const char* p = nullptr;
            if (sd_bus_message_read(reply, "o", &p) >= 0 && p && *p) {
                uw.path = p;
                res = ResolveResult::Resolved;
            } else {
                res = ResolveResult::NotFound;
            }
        } else if (systemd_error_name_is_absence(err.name ? err.name : "")) {
            res = ResolveResult::NotFound;
        } else {
            spdlog::warn("spark_service: LoadUnit '{}' transient error (name='{}', {}) — "
                         "reopening, no false Stopped",
                         uw.unit, err.name ? err.name : "(none)",
                         err.message ? err.message : err_str(r < 0 ? -r : 0));
            res = ResolveResult::BusError;
        }
        if (reply)
            sd_bus_message_unref(reply);
        sd_bus_error_free(&err);
        return res;
    }

    // nullopt only on a bare TRANSPORT failure (bus gone) — never on a genuine
    // Absent, which is a real terminal state (mirrors guard_systemd.cpp).
    std::optional<SystemdState> read_state(sd_bus* bus, UnitWatch& uw) {
        if (uw.path.empty())
            return SystemdState::Absent;
        sd_bus_error err = SD_BUS_ERROR_NULL;
        char* s = nullptr;
        std::optional<SystemdState> st;
        int r = sd_bus_get_property_string(bus, kDest, uw.path.c_str(), kUnitIface, "ActiveState",
                                           &err, &s);
        if (r >= 0 && s) {
            st = parse_active_state(s);
        } else if (systemd_error_name_is_absence(err.name ? err.name : "")) {
            st = SystemdState::Absent;
        } else {
            spdlog::warn("spark_service: ActiveState read transient error for '{}' (name='{}') — "
                         "reopening, no false drift",
                         uw.unit, err.name ? err.name : "(none)");
        }
        if (s)
            free(s);
        sd_bus_error_free(&err);
        return st;
    }

    // Collects an emit for every key on `uw` if the mapped terminal state is a
    // real edge vs. `uw.last`; transitional states are held (no compare, no
    // commit) per spark.hpp's documented contract.
    void set_terminal(UnitWatch& uw, ServiceRunState mapped, std::vector<PendingEmit>& out) {
        if (uw.last && *uw.last == mapped)
            return; // no-edge, silent
        uw.last = mapped;
        for (const auto& k : uw.keys)
            out.push_back({k, mapped});
    }

    void set_terminal_from_systemd(UnitWatch& uw, SystemdState st, std::vector<PendingEmit>& out) {
        if (systemd_state_is_transitional(st))
            return; // HELD — never emitted, never moves the edge-dedup baseline
        set_terminal(uw, map_terminal(st), out);
    }

    // (Re)resolve + (re)arm the PropertiesChanged match for `uw` from scratch —
    // drops any prior slot first. Collects an initial/re-resolved emit for
    // every current key on `uw`. Sets bus_ok_=false on a transport failure
    // (caller reopens); never fabricates a false Stopped on that path.
    // `faults` lets arm_unit report a bus failure it discovers itself
    // (governance Gate-4 unhappy-path finding, UP-1): the three call sites
    // below previously only fed a fresh BusError into `bus_ok_`, relying on
    // the main loop's OWN process/read failure sites to call fault_all — but
    // a re-arm invoked from Cmd::Add, the healthy-reconcile backstop loop, or
    // the reopen-success re-arm-all pass could discover the SAME class of
    // failure without ever routing through those two call sites, silently
    // swallowing the fault signal for every unit on the connection.
    void arm_unit(sd_bus* bus, UnitWatch& uw, std::vector<PendingEmit>& emits,
                  std::vector<PendingFault>& faults) {
        uw.slot.reset(); // drop the old match (and its bus ref) first
        switch (resolve_path(bus, uw)) {
        case ResolveResult::BusError:
            bus_ok_ = false;
            fault_all(true, "system bus lost", faults);
            uw.next_backstop = std::chrono::steady_clock::now() +
                               std::chrono::milliseconds(kAbsentRetryMs);
            return;
        case ResolveResult::NotFound:
            uw.path.clear();
            set_terminal(uw, ServiceRunState::Stopped, emits);
            uw.next_backstop = std::chrono::steady_clock::now() +
                               std::chrono::milliseconds(kAbsentRetryMs);
            return;
        case ResolveResult::Resolved:
            break;
        }
        sd_bus_slot* slot = nullptr;
        int r = sd_bus_match_signal(bus, &slot, kDest, uw.path.c_str(), kPropsIface,
                                    "PropertiesChanged", &on_props_changed, &uw);
        if (r < 0) {
            spdlog::warn("spark_service: match arm failed for '{}': {}", uw.unit, err_str(-r));
            if (auto st = read_state(bus, uw)) {
                set_terminal_from_systemd(uw, *st, emits);
            } else {
                bus_ok_ = false;
                fault_all(true, "system bus lost", faults);
            }
            uw.next_backstop = std::chrono::steady_clock::now() +
                               std::chrono::milliseconds(kAbsentRetryMs);
            return;
        }
        uw.slot.reset(slot);
        if (auto st = read_state(bus, uw)) {
            set_terminal_from_systemd(uw, *st, emits);
        } else {
            bus_ok_ = false;
            fault_all(true, "system bus lost", faults);
        }
        uw.next_backstop = std::chrono::steady_clock::now() +
                           std::chrono::milliseconds(kHealthyReconcileMs);
    }

    // Edge-gated per-unit fault fan-out: fires fault_(key,faulted,reason) for
    // every key on a unit whose faulted state is actually changing (never every
    // tick), mirroring spark_registry.cpp's per-key fault edge discipline.
    void fault_all(bool faulted, std::string_view reason, std::vector<PendingFault>& out) {
        for (auto& [name, uwp] : units_) {
            if (uwp->faulted == faulted)
                continue;
            uwp->faulted = faulted;
            for (const auto& k : uwp->keys)
                out.push_back({k, faulted, std::string(reason)});
        }
    }

    void dispatch(std::vector<PendingEmit>& emits, std::vector<PendingFault>& faults) {
        for (auto& e : emits)
            if (emit_)
                emit_(e.key, SparkData{ServiceSparkData{e.state}});
        emits.clear();
        for (auto& f : faults)
            if (fault_)
                fault_(f.key, f.faulted, f.reason);
        faults.clear();
    }

    void run() try {
        auto* bus = static_cast<sd_bus*>(bus_);
        bus_ok_ = true;
        std::vector<PendingEmit> emits;
        std::vector<PendingFault> faults;

        // Subscribe so systemd emits unit signals to us at all — non-fatal if
        // it fails (degrades to the bounded backstop reconcile only), mirrors
        // guard_systemd.cpp's subscribe(). Re-run after every reopen.
        auto subscribe = [&] {
            sd_bus_error err = SD_BUS_ERROR_NULL;
            sd_bus_message* reply = nullptr;
            if (sd_bus_call_method(bus, kDest, kMgrPath, kMgrIface, "Subscribe", &err, &reply, "") <
                0)
                spdlog::warn("spark_service: Subscribe failed ({}) — falling back to bounded "
                             "reconcile only",
                             err.message ? err.message : "(none)");
            if (reply)
                sd_bus_message_unref(reply);
            sd_bus_error_free(&err);
        };
        subscribe();

        while (!stop_.load(std::memory_order_acquire)) {
            // 1) Drain queued bus messages while healthy (dispatches matches ->
            //    sets dirty). A transport failure flips bus_ok_ and faults every
            //    watched key at once.
            if (bus_ok_) {
                for (;;) {
                    int r = sd_bus_process(bus, nullptr);
                    if (r < 0) {
                        spdlog::warn("spark_service: bus lost ({}) — reconnecting", err_str(-r));
                        bus_ok_ = false;
                        fault_all(true, "system bus lost", faults);
                        break;
                    }
                    if (stop_.load(std::memory_order_acquire) || r == 0)
                        break;
                }
                if (stop_.load(std::memory_order_acquire))
                    break;
            }

            // 2) Re-read every dirty unit.
            if (bus_ok_) {
                for (auto& [name, uwp] : units_) {
                    if (!uwp->dirty)
                        continue;
                    uwp->dirty = false;
                    if (auto st = read_state(bus, *uwp)) {
                        set_terminal_from_systemd(*uwp, *st, emits);
                    } else {
                        bus_ok_ = false;
                        fault_all(true, "system bus lost", faults);
                        break;
                    }
                }
            }

            // 3) Drain pending watch()/unwatch() commands.
            std::deque<Cmd> cmds;
            {
                std::lock_guard lk(mu_);
                cmds.swap(pending_);
            }
            for (auto& cmd : cmds) {
                if (cmd.op == Cmd::Add) {
                    if (key_unit_.contains(cmd.key))
                        continue; // idempotent — this key is already watched
                    auto it = units_.find(cmd.unit);
                    const bool is_new_unit = (it == units_.end());
                    UnitWatch* uw;
                    if (is_new_unit) {
                        auto owned = std::make_unique<UnitWatch>();
                        owned->unit = cmd.unit;
                        uw = owned.get();
                        units_.emplace(cmd.unit, std::move(owned));
                    } else {
                        uw = it->second.get();
                    }
                    uw->keys.insert(cmd.key);
                    key_unit_.emplace(cmd.key, cmd.unit);
                    if (is_new_unit) {
                        if (bus_ok_) {
                            arm_unit(bus, *uw, emits, faults);
                        } else {
                            // Bus is down: this key is faulted from the moment
                            // it arms; reopen's re-arm-all pass will resolve it.
                            // MUST set next_backstop — a fresh UnitWatch's
                            // default-constructed time_point{} sentinel sorts
                            // before `now` in the poll-timeout computation
                            // below, collapsing it to 0 and busy-looping
                            // sd_bus_open_system every iteration until the bus
                            // recovers (governance Gate-3 cpp-expert finding).
                            uw->faulted = true;
                            uw->next_backstop = std::chrono::steady_clock::now() +
                                                std::chrono::milliseconds(kAbsentRetryMs);
                            faults.push_back({cmd.key, true, "system bus lost"});
                        }
                    } else if (uw->last) {
                        // An existing (already-resolved) unit gains a new
                        // subscriber key — give it the initial state too, since
                        // engine subscribers are keyed per-spec. If the unit is
                        // currently faulted, tell the new key that too (UP-2,
                        // governance Gate-4 unhappy-path) — otherwise it'd be
                        // handed a cached value the mechanism doesn't itself
                        // trust yet, with no fault signal until the NEXT edge.
                        emits.push_back({cmd.key, *uw->last});
                        if (uw->faulted)
                            faults.push_back({cmd.key, true, "system bus lost"});
                    }
                } else { // Cmd::Remove
                    auto kit = key_unit_.find(cmd.key);
                    if (kit == key_unit_.end())
                        continue; // unknown/already-removed key — idempotent
                    const std::string unit = kit->second;
                    key_unit_.erase(kit);
                    auto uit = units_.find(unit);
                    if (uit == units_.end())
                        continue;
                    uit->second->keys.erase(cmd.key);
                    if (uit->second->keys.empty())
                        units_.erase(uit); // slot RAII releases the match here
                }
            }

            // 4) Dispatch everything collected above — with NO lock held.
            dispatch(emits, faults);
            if (stop_.load(std::memory_order_acquire))
                break;

            // 5) Compute the poll timeout: soonest per-unit backstop, capped by
            //    sd-bus's own next-operation deadline while healthy.
            const auto now = std::chrono::steady_clock::now();
            auto next = now + std::chrono::milliseconds(kHealthyReconcileMs);
            for (auto& [name, uwp] : units_)
                if (uwp->next_backstop < next)
                    next = uwp->next_backstop;
            long long timeout_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(next - now).count();
            if (timeout_ms < 0)
                timeout_ms = 0;
            if (!bus_ok_)
                timeout_ms = std::min<long long>(timeout_ms, static_cast<long long>(kAbsentRetryMs));
            if (bus_ok_) {
                std::uint64_t bus_to_us = UINT64_MAX;
                if (sd_bus_get_timeout(bus, &bus_to_us) >= 0 && bus_to_us != UINT64_MAX) {
                    const std::uint64_t now_us = monotonic_us();
                    const long long bus_ms = bus_to_us > now_us
                                                 ? static_cast<long long>((bus_to_us - now_us) / 1000)
                                                 : 0;
                    if (bus_ms < timeout_ms)
                        timeout_ms = bus_ms;
                }
            }

            // While the bus is dead we poll ONLY the wake eventfd — never the
            // stale bus fd (would busy-spin on a closed/HUP fd).
            struct pollfd fds[2];
            int wake_idx;
            int nfds;
            if (bus_ok_) {
                fds[0] = {sd_bus_get_fd(bus), static_cast<short>(sd_bus_get_events(bus)), 0};
                fds[1] = {wake_fd_, POLLIN, 0};
                wake_idx = 1;
                nfds = 2;
            } else {
                fds[0] = {wake_fd_, POLLIN, 0};
                wake_idx = 0;
                nfds = 1;
            }
            int pr = ::poll(fds, nfds, static_cast<int>(timeout_ms));
            if (pr < 0) {
                if (errno == EINTR)
                    continue;
                // Unrecoverable — the mechanism thread is about to exit and
                // every currently-armed key will silently stop updating
                // forever. Report it: without this, mechanism death is
                // indistinguishable from "healthy and quiet" in the engine's
                // stats (governance Gate-6 sre finding — a more severe
                // version of the re-arm fault-swallowing bug fixed earlier
                // this round).
                spdlog::error("spark_service: poll failed ({}) — mechanism thread exiting, "
                             "every armed key is now silently dead",
                             err_str(errno));
                fault_all(true, "mechanism thread terminating", faults);
                // fault_all only covers already-armed units — a watch() that
                // landed in pending_ this same tick was never armed at all,
                // so it has no units_ entry for fault_all to find. Without
                // this, a consumer whose arm() call raced the mechanism's
                // death would get no signal whatsoever (governance Gate-4
                // unhappy-path finding UP-8). Cmd::Remove entries need no
                // signal — nothing was ever told they existed.
                {
                    std::lock_guard lk(mu_);
                    for (auto& cmd : pending_)
                        if (cmd.op == Cmd::Add)
                            faults.push_back({cmd.key, true, "mechanism thread terminating"});
                    pending_.clear();
                }
                dispatch(emits, faults);
                break;
            }
            if (fds[wake_idx].revents & POLLIN) {
                // eventfd is counter-semantics + level-triggered: an unread
                // write leaves it readable forever, busy-spinning poll() at
                // 100% CPU and starving the backstop/reopen block below on
                // every subsequent iteration (governance finding, PR #1927
                // review). Drain the counter before looping back to the top.
                std::uint64_t drained = 0;
                ssize_t n;
                do {
                    n = ::read(wake_fd_, &drained, sizeof(drained));
                } while (n < 0 && errno == EINTR);
                continue; // a command was enqueued or stop() signalled — loop re-checks at the top
            }

            // 6) Backstop expiry: reopen the bus if down, else re-arm any unit
            //    whose reconcile deadline passed.
            if (!bus_ok_) {
                sd_bus* nb = nullptr;
                if (sd_bus_open_system(&nb) >= 0 && nb) {
                    // Slot-before-bus: drop every unit's match (each holds a
                    // ref on the OLD connection) before releasing our own
                    // reference to it — mirrors guard_systemd.cpp's
                    // reopen_bus ordering. Without this, `bus = nb` below
                    // loses the only pointer that could ever unref the old
                    // connection, permanently leaking it + its fd on every
                    // reconnect (governance Gate-2 security-guardian finding)
                    // — arm_unit()'s own slot.reset() runs against the NEW
                    // bus pointer by the time it executes below, too late to
                    // release the old one.
                    for (auto& [name, uwp] : units_)
                        uwp->slot.reset();
                    if (bus) {
                        sd_bus_flush(bus);
                        sd_bus_unref(bus);
                    }
                    bus = nb;
                    bus_ = nb;
                    subscribe();
                    bus_ok_ = true;
                    // Don't declare "recovered" until the re-arm pass below
                    // actually confirms the connection is still usable — a
                    // bus that reopens but is dead-on-first-use would
                    // otherwise flap recovered→faulted within the same
                    // dispatch batch (governance Gate-6 sre finding).
                    for (auto& [name, uwp] : units_) {
                        arm_unit(bus, *uwp, emits, faults);
                        if (!bus_ok_)
                            break; // the connection died again mid-pass — fault_all(true)
                                   // inside arm_unit already covers every unit including
                                   // the ones not yet reached; re-trying them against the
                                   // same known-broken connection would be redundant and,
                                   // if one happened to transiently succeed, would leave it
                                   // stuck reporting faulted=true (set for ALL units by that
                                   // fault_all call) despite emitting healthy data — no
                                   // per-unit success clears a fault, only the NEXT reopen's
                                   // recovered edge does (governance Gate-3 cpp-expert finding)
                    }
                    if (bus_ok_)
                        fault_all(false, "recovered", faults); // only now confirmed still up
                    dispatch(emits, faults);
                    spdlog::info("spark_service: system bus reconnected");
                } else {
                    if (nb)
                        sd_bus_unref(nb);
                    // stays down; retried again after kAbsentRetryMs
                }
            } else {
                const auto now2 = std::chrono::steady_clock::now();
                for (auto& [name, uwp] : units_) {
                    if (uwp->next_backstop > now2)
                        continue;
                    arm_unit(bus, *uwp, emits, faults);
                    if (!bus_ok_)
                        break; // same reasoning as the reopen-rearm-all loop above
                }
                dispatch(emits, faults);
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("spark_service: poll thread exception: {} — mechanism stopping", e.what());
    } catch (...) {
        spdlog::error("spark_service: poll thread unknown exception — mechanism stopping");
    }

    /// Serialises start() and stop() END TO END against each other and against themselves,
    /// so a second stop() (typically ~LinuxServiceMechanism) WAITS for an in-flight
    /// teardown instead of racing it into a double sd_bus_unref / double close(), and a
    /// start() cannot assign thread_/bus_/wake_fd_ while a stop() is joining and freeing
    /// them. Held across the join; mu_ is NOT (the poll thread needs it).
    /// LOCK ORDER: teardown_mu_ → mu_. Never the reverse.
    std::mutex teardown_mu_;
    std::mutex mu_;                    ///< guards ONLY pending_ + the start/stop/inert flags
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    std::deque<Cmd> pending_;
    bool started_{false};
    /// The system bus never opened at start() — permanent for this instance. THE
    /// COMMON CASE IS A CONTAINER: Dockerfile.agent ships libsystemd0, but a container
    /// has no system bus, so every containerized Linux agent lands here. Atomic so
    /// stats() (const, heartbeat thread) can publish it without mu_ — otherwise the
    /// mechanism stays REGISTERED and the fleet reads a service capability that can
    /// never watch anything (governance Gate-3 cross-platform / Gate-6 sre).
    std::atomic<bool> inert_{false};
    std::atomic<bool> stop_{false};
    std::thread thread_;
    void* bus_{nullptr};               ///< sd_bus* (void* keeps sd-bus.h out of the mechanism's shape)
    int wake_fd_{-1};

    // Poll-thread-confined (no lock): touched only from run(), and from stop()
    // after the thread has joined.
    bool bus_ok_{true};
    std::unordered_map<std::string, std::unique_ptr<UnitWatch>> units_; ///< keyed by normalized unit name
    std::unordered_map<std::string, std::string> key_unit_;            ///< spark key -> normalized unit name
};

} // namespace

std::unique_ptr<ISparkMechanism> make_service_mechanism() {
    return std::make_unique<LinuxServiceMechanism>();
}

} // namespace yuzu::agent

#elif defined(_WIN32)

// ═══════════════════════════════════════════════════════════════════════════
// Windows: one SCM connection + one alertable-wait thread, multiplexing N
// service watches. NotifyServiceStatusChangeW delivers via APC to the
// REGISTERING thread, so every registration must happen on the one mechanism
// thread — the same fire-and-forget command queue as Linux, and for the same
// reason: the APC-processing thread IS the emit thread, so a synchronous
// watch() that waited on itself would deadlock on every inline re-arm.
// ═══════════════════════════════════════════════════════════════════════════

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "guard_win_handle.hpp" // detail::EventHandle

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <win_sc_handle.hpp> // shared yuzu::win::ScHandle — CloseServiceHandle RAII (#1822)
#include <win_str.hpp>       // shared yuzu::win wide<->UTF-8 helpers (#1681)

#pragma comment(lib, "advapi32.lib")

namespace yuzu::agent {
namespace {

using yuzu::win::to_wide;

// Identical charset gate to guard_service.cpp's local valid_service_name —
// defence-in-depth if a malformed name slips past the server-side authoring
// validator (the engine's own valid_unit_name check already rejects it first
// on this shared Linux/Windows token vocabulary, so this is redundant-safe).
bool valid_service_name(const std::string& name) {
    if (name.empty() || name.size() > 256)
        return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '_' && c != '-' &&
            c != '@')
            return false;
    }
    return true;
}

// Locale-independent case fold for the service-name map key (SCM names are
// case-insensitive) — mirrors spark_file.cpp's fold_ci via LCMapStringEx.
std::wstring fold_ci(std::wstring_view s) {
    if (s.empty())
        return {};
    const int n = ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.data(),
                                  static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr, 0);
    if (n <= 0)
        return std::wstring(s);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.data(), static_cast<int>(s.size()),
                    out.data(), n, nullptr, nullptr, 0);
    return out;
}

// All run-state transitions; deliberately NOT SERVICE_NOTIFY_CREATED / DELETED
// / DELETE_PENDING — those are SCM-handle-only flags that make
// NotifyServiceStatusChange fail with ERROR_INVALID_PARAMETER (87) on a
// SERVICE handle (found only in Windows UAT). Copied verbatim from
// guard_service.cpp, including the regression-guard static_assert.
constexpr DWORD kNotifyMask = SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED |
                              SERVICE_NOTIFY_START_PENDING | SERVICE_NOTIFY_STOP_PENDING |
                              SERVICE_NOTIFY_CONTINUE_PENDING | SERVICE_NOTIFY_PAUSE_PENDING |
                              SERVICE_NOTIFY_PAUSED;

static_assert((kNotifyMask & (SERVICE_NOTIFY_CREATED | SERVICE_NOTIFY_DELETED |
                              SERVICE_NOTIFY_DELETE_PENDING)) == 0,
              "kNotifyMask must not contain SCM-handle-only notify flags (CREATED/DELETED/"
              "DELETE_PENDING) — they fail with ERROR_INVALID_PARAMETER on a service handle");

constexpr std::uint64_t kAbsentRetryMs = 30000;

/// How many main-loop passes a retired SvcWatch survives in `retiring_`
/// before being freed for real, once it stops observing any further APC
/// delivery. Reset back to this value any time a stale APC DOES land during
/// retirement, so a watch that keeps firing (an SCM that queued several
/// notifications before the close landed) never gets freed mid-delivery.
constexpr int kRetireGracePasses = 3;

/// Bounds the fired-flag fixed-point scan (see its call site in run()) so a
/// pathologically flapping service can't monopolize the mechanism thread.
constexpr int kMaxFiredScanPasses = 16;

bool is_pending(DWORD s) {
    return s == SERVICE_START_PENDING || s == SERVICE_STOP_PENDING ||
           s == SERVICE_CONTINUE_PENDING || s == SERVICE_PAUSE_PENDING;
}

ServiceRunState map_terminal(DWORD s) {
    switch (s) {
    case SERVICE_RUNNING: return ServiceRunState::Running;
    case SERVICE_PAUSED:  return ServiceRunState::Paused;
    default:              return ServiceRunState::Stopped; // SERVICE_STOPPED (pending handled earlier)
    }
}

struct PendingEmit {
    std::string key;
    ServiceRunState state;
};
struct PendingFault {
    std::string key;
    bool faulted;
    std::string reason;
};

/// One watched Windows service, mechanism-thread-confined. `notify` MUST
/// outlive each one-shot registration (the SCM writes into it via APC);
/// `pContext` points back at this struct so the APC callback can identify
/// which service fired among N multiplexed on the one thread.
struct SvcWatch {
    // RAII for pszServiceNames: teardown_watch()/the reap loop free it on
    // their own paths, but WAIT_FAILED and the run()-exit catch blocks tear
    // svcs_/retiring_ down without ever reaping a still-fired entry first —
    // this destructor makes every teardown path safe uniformly, rather than
    // relying on the reap loop alone (governance re-review LOW finding).
    ~SvcWatch() {
        if (notify.pszServiceNames)
            LocalFree(notify.pszServiceNames);
    }

    std::wstring name; ///< folded (case-insensitive); map key in svcs_
    std::set<std::string> keys;
    yuzu::win::ScHandle svc; ///< SERVICE_QUERY_STATUS
    SERVICE_NOTIFYW notify{};
    bool registered{false};
    // APC-filled; same-thread invariant (guard_service.cpp's WatchCtx precedent)
    // — the callback runs only during THIS thread's alertable wait, never
    // concurrently with the rest of the loop.
    bool fired{false};
    DWORD notify_status{ERROR_SUCCESS};
    DWORD current_state{0};
    std::optional<ServiceRunState> last;
    bool faulted{false};
    std::chrono::steady_clock::time_point next_retry{};
    /// >0 while parked in `retiring_` awaiting quiescence before real free;
    /// 0 for a live (non-retiring) watch. See `retiring_`'s doc comment.
    int retire_grace{0};
};

void CALLBACK notify_cb(PVOID param) {
    auto* n = static_cast<SERVICE_NOTIFYW*>(param);
    auto* w = static_cast<SvcWatch*>(n->pContext);
    w->notify_status = n->dwNotificationStatus;
    w->current_state = n->ServiceStatus.dwCurrentState;
    w->fired = true;
}

/// Windows Service spark mechanism: ONE SCM connection + ONE alertable-wait
/// thread service every armed service watch (N service handles are
/// unavoidable — NotifyServiceStatusChangeW needs one per service). Same
/// fire-and-forget command queue as the Linux mechanism, for the identical
/// inline-re-arm-safety reason (see the file header comment).
class WindowsServiceMechanism final : public ISparkMechanism {
public:
    ~WindowsServiceMechanism() override { stop(); }

    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        std::lock_guard lk(mu_);
        if (started_)
            return; // idempotent
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        scm_.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm_) {
            spdlog::warn("spark_service: OpenSCManager failed (err={}) — service sparks inert on "
                         "this host",
                         GetLastError());
            scm_ok_ = false;
            started_inert_.store(true, std::memory_order_release);
            started_ = true;
            return;
        }
        wake_.reset(CreateEventW(nullptr, /*manualReset=*/FALSE, /*initial=*/FALSE, nullptr));
        if (!wake_) {
            scm_.reset();
            scm_ok_ = false;
            started_inert_.store(true, std::memory_order_release);
            started_ = true;
            return;
        }
        scm_ok_ = true;
        started_inert_.store(false, std::memory_order_release);
        stop_.store(false, std::memory_order_release);
        thread_ = std::thread([this] { run(); });
        started_ = true;
    }

    std::expected<void, std::string> watch(const std::string& key,
                                           const SparkParams& params) override {
        const auto* sp = std::get_if<ServiceSparkParams>(&params);
        if (!sp)
            return std::unexpected("service mechanism: params are not ServiceSparkParams");
        if (!valid_service_name(sp->service_name))
            return std::unexpected("service mechanism: invalid service name '" +
                                   sp->service_name + "'");
        std::lock_guard lk(mu_);
        if (!started_)
            return std::unexpected("service mechanism not started");
        if (!scm_ok_)
            return std::unexpected("SCM unavailable — service sparks unsupported on this host");
        pending_.push_back(Cmd{Cmd::Add, key, to_wide(sp->service_name)});
        wake_signal();
        return {};
    }

    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        if (!started_ || !scm_ok_)
            return;
        pending_.push_back(Cmd{Cmd::Remove, key, {}});
        wake_signal();
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            if (!started_)
                return; // idempotent
            started_ = false;
        }
        if (thread_.joinable()) {
            stop_.store(true, std::memory_order_release);
            wake_signal();
            thread_.join();
        }
        // The mechanism thread has joined — every SvcWatch's registration was
        // already torn down by the thread's own exit path (see run(), and its
        // duplication into both catch blocks); svcs_/retiring_ are now safe
        // to touch without a lock.
        svcs_.clear();
        retiring_.clear();
        key_svc_.clear();
        scm_.reset();
        wake_.reset();
        std::lock_guard lk(mu_);
        emit_ = nullptr;
        fault_ = nullptr;
        scm_ok_ = false;
        started_inert_.store(false, std::memory_order_release);
        pending_.clear();
    }

    /// See the Linux twin: this mechanism tracks none of the File-mechanism counters,
    /// but it MUST publish `inert` so an SCM-denied service mechanism is distinguishable
    /// from a healthy idle one.
    [[nodiscard]] SparkMechanismStats stats() const override {
        return {.inert = started_inert_.load(std::memory_order_acquire)};
    }

private:
    struct Cmd {
        enum Op { Add, Remove } op;
        std::string key;
        std::wstring name; // only meaningful for Add
    };

    void wake_signal() {
        if (wake_)
            SetEvent(wake_.get());
    }

    // ── Mechanism-thread-confined helpers ───────────────────────────────────

    // Cancels the outstanding registration (closing the handle invalidates it),
    // drains any APC already queued for it via an alertable no-op wait (the
    // SERVICE_NOTIFYW UAF hazard — a queued APC must never run after the
    // struct is freed), then releases the name buffer.
    void teardown_watch(SvcWatch& w) {
        w.svc.reset();
        SleepEx(0, TRUE); // drain any already-queued APC for this registration
        if (w.notify.pszServiceNames) {
            LocalFree(w.notify.pszServiceNames);
            w.notify.pszServiceNames = nullptr;
        }
    }

    // (Re)open the service handle + (re)register the one-shot notify from
    // scratch. Collects an initial/re-resolved emit for every current key on
    // `w`. `ERROR_SERVICE_DOES_NOT_EXIST` is a genuine terminal Stopped, never
    // a fault; every other open/register failure is a fault (never a false
    // Stopped — the UP-4 class guard_systemd.cpp's ResolveResult split guards
    // against on Linux).
    void arm_watch(SvcWatch& w, std::vector<PendingEmit>& emits, std::vector<PendingFault>& faults) {
        teardown_watch(w);
        SC_HANDLE h = OpenServiceW(scm_.get(), w.name.c_str(), SERVICE_QUERY_STATUS);
        if (!h) {
            const DWORD err = GetLastError();
            if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
                set_terminal(w, ServiceRunState::Stopped, emits);
                if (w.faulted) {
                    w.faulted = false;
                    for (const auto& k : w.keys)
                        faults.push_back({k, false, "recovered"});
                }
            } else {
                spdlog::warn("spark_service: OpenService failed for a watched service (err={})",
                             err);
                if (!w.faulted) {
                    w.faulted = true;
                    for (const auto& k : w.keys)
                        faults.push_back({k, true, "OpenService failed"});
                }
            }
            w.next_retry = std::chrono::steady_clock::now() +
                           std::chrono::milliseconds(kAbsentRetryMs);
            return;
        }
        w.svc.reset(h);
        w.notify = SERVICE_NOTIFYW{};
        w.notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
        w.notify.pfnNotifyCallback = &notify_cb;
        w.notify.pContext = &w;
        const DWORD rc = NotifyServiceStatusChangeW(w.svc.get(), kNotifyMask, &w.notify);
        if (rc != ERROR_SUCCESS) {
            spdlog::warn("spark_service: NotifyServiceStatusChange failed (rc={}) — degraded "
                         "re-arm in {}ms",
                         rc, kAbsentRetryMs);
            w.svc.reset();
            if (!w.faulted) {
                w.faulted = true;
                for (const auto& k : w.keys)
                    faults.push_back({k, true, "NotifyServiceStatusChange failed"});
            }
            w.next_retry = std::chrono::steady_clock::now() +
                           std::chrono::milliseconds(kAbsentRetryMs);
            return;
        }
        // Registered — the immediate callback (and every later terminal
        // transition) delivers as an APC at the next alertable wait.
        if (w.faulted) {
            w.faulted = false;
            for (const auto& k : w.keys)
                faults.push_back({k, false, "recovered"});
        }
        w.next_retry = {}; // event-driven now; no polling backstop needed while armed
    }

    void set_terminal(SvcWatch& w, ServiceRunState mapped, std::vector<PendingEmit>& out) {
        if (w.last && *w.last == mapped)
            return;
        w.last = mapped;
        for (const auto& k : w.keys)
            out.push_back({k, mapped});
    }

    void dispatch(std::vector<PendingEmit>& emits, std::vector<PendingFault>& faults) {
        for (auto& e : emits)
            if (emit_)
                emit_(e.key, SparkData{ServiceSparkData{e.state}});
        emits.clear();
        for (auto& f : faults)
            if (fault_)
                fault_(f.key, f.faulted, f.reason);
        faults.clear();
    }

    void run() try {
        std::vector<PendingEmit> emits;
        std::vector<PendingFault> faults;

        while (!stop_.load(std::memory_order_acquire)) {
            // Compute the wait timeout: soonest per-service retry deadline.
            const auto now = std::chrono::steady_clock::now();
            bool have_deadline = false;
            auto next = now;
            for (auto& [name, wp] : svcs_) {
                if (wp->next_retry == std::chrono::steady_clock::time_point{})
                    continue; // event-driven, no polling backstop
                if (!have_deadline || wp->next_retry < next) {
                    next = wp->next_retry;
                    have_deadline = true;
                }
            }
            DWORD timeout = INFINITE;
            if (have_deadline) {
                const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(next - now)
                                    .count();
                timeout = static_cast<DWORD>(std::clamp<long long>(ms, 0, 0xFFFFFFFEll));
            }

            const DWORD r = WaitForSingleObjectEx(wake_.get(), timeout, /*alertable=*/TRUE);
            if (stop_.load(std::memory_order_acquire))
                break;

            if (r != WAIT_OBJECT_0 && r != WAIT_TIMEOUT && r != WAIT_IO_COMPLETION) {
                // WAIT_FAILED — unrecoverable. The mechanism thread is about
                // to exit and every currently-armed key will silently stop
                // updating forever; report it (governance Gate-6 sre
                // finding — this path previously had no log line at all).
                spdlog::error("spark_service: WaitForSingleObjectEx failed (err={}) — mechanism "
                             "thread exiting, every armed key is now silently dead",
                             GetLastError());
                for (auto& [name, wp] : svcs_) {
                    if (wp->faulted)
                        continue;
                    wp->faulted = true;
                    for (const auto& k : wp->keys)
                        faults.push_back({k, true, "mechanism thread terminating"});
                }
                // Same reasoning as the Linux mechanism: a watch() that
                // landed in pending_ this same tick was never armed at all,
                // so the loop above (which only walks svcs_) can't find it —
                // without this, a consumer whose arm() call raced the
                // mechanism's death would get no signal whatsoever
                // (governance Gate-4 unhappy-path finding UP-8).
                {
                    std::lock_guard lk(mu_);
                    for (auto& cmd : pending_)
                        if (cmd.op == Cmd::Add)
                            faults.push_back({cmd.key, true, "mechanism thread terminating"});
                    pending_.clear();
                }
                dispatch(emits, faults);
                break;
            }

            if (r == WAIT_TIMEOUT) {
                const auto now2 = std::chrono::steady_clock::now();
                for (auto& [name, wp] : svcs_) {
                    if (wp->next_retry == std::chrono::steady_clock::time_point{} ||
                        wp->next_retry > now2)
                        continue;
                    arm_watch(*wp, emits, faults); // may deliver APCs via its own SleepEx(0,TRUE)
                }
            }

            // Drain pending watch()/unwatch() commands. Add's arm_watch (and
            // Remove's teardown_watch) may ALSO deliver queued APCs via their
            // internal SleepEx(0,TRUE) — the fired-flag scan below runs AFTER
            // this drain so it catches those too.
            std::deque<Cmd> cmds;
            {
                std::lock_guard lk(mu_);
                cmds.swap(pending_);
            }
            for (auto& cmd : cmds) {
                if (cmd.op == Cmd::Add) {
                    if (key_svc_.contains(cmd.key))
                        continue; // idempotent
                    const std::wstring folded = fold_ci(cmd.name);
                    auto it = svcs_.find(folded);
                    const bool is_new = (it == svcs_.end());
                    SvcWatch* w;
                    if (is_new) {
                        auto owned = std::make_unique<SvcWatch>();
                        owned->name = cmd.name;
                        w = owned.get();
                        svcs_.emplace(folded, std::move(owned));
                    } else {
                        w = it->second.get();
                    }
                    w->keys.insert(cmd.key);
                    key_svc_.emplace(cmd.key, folded);
                    if (is_new) {
                        arm_watch(*w, emits, faults);
                    } else if (w->last) {
                        // Same UP-2 fix as the Linux mechanism: hand a
                        // newly-coalescing key the fault status too, not just
                        // the cached state.
                        emits.push_back({cmd.key, *w->last});
                        if (w->faulted)
                            faults.push_back({cmd.key, true, "OpenService failed"});
                    }
                } else { // Cmd::Remove
                    auto kit = key_svc_.find(cmd.key);
                    if (kit == key_svc_.end())
                        continue;
                    const std::wstring folded = kit->second;
                    key_svc_.erase(kit);
                    auto sit = svcs_.find(folded);
                    if (sit == svcs_.end())
                        continue;
                    sit->second->keys.erase(cmd.key);
                    if (sit->second->keys.empty()) {
                        // Don't free the SvcWatch synchronously: CloseServiceHandle
                        // cancelling a pending NotifyServiceStatusChangeW
                        // registration is not documented as a synchronous
                        // barrier against an already-in-flight APC (governance
                        // Gate-2 security-guardian finding) — a queued
                        // notification could still land microseconds after
                        // teardown_watch's drain. Relocate to retiring_ (kept
                        // alive, never re-armed, no keys so nothing to notify)
                        // and free only once quiescent for a few loop passes.
                        teardown_watch(*sit->second);
                        sit->second->retire_grace = kRetireGracePasses;
                        retiring_.push_back(std::move(sit->second));
                        svcs_.erase(sit);
                    }
                }
            }

            // Unconditionally scan every watch for a delivered APC notification
            // — regardless of what `r` was. An APC is NOT only delivered by the
            // WaitForSingleObjectEx above (which used to be the only trigger
            // this scan ran on, r==WAIT_IO_COMPLETION): arm_watch/teardown_watch
            // call SleepEx(0,TRUE) to drain a registration's queued APC, and
            // THAT alertable point can just as easily deliver an unrelated
            // watch's fresh notification. That happens inside the WAIT_TIMEOUT
            // reconcile above and inside this iteration's Add/Remove command
            // drain — gating the scan on r==WAIT_IO_COMPLETION silently missed
            // those, leaving a watch's one-shot consumed-but-unprocessed until
            // some unrelated later fire happened to re-scan it. Loop until a
            // full pass finds nothing new: this scan's OWN arm_watch calls
            // (the MARKED_FOR_DELETE / re-arm-failed branches) can themselves
            // deliver another watch's queued APC via the same SleepEx path.
            // Bounded to kMaxFiredScanPasses (governance Gate-3 cpp-expert
            // finding): a service flapping externally faster than this thread
            // can re-arm+drain could otherwise re-seed `fired` every pass
            // indefinitely, monopolizing the mechanism thread. A self-wake on
            // hitting the cap defers any straggler to the next outer-loop
            // iteration rather than looping unbounded here.
            for (int pass = 0; pass < kMaxFiredScanPasses; ++pass) {
                bool any = false;
                for (auto& [name, wp] : svcs_) {
                    if (!wp->fired)
                        continue;
                    any = true;
                    wp->fired = false;
                    if (wp->notify.pszServiceNames) {
                        LocalFree(wp->notify.pszServiceNames);
                        wp->notify.pszServiceNames = nullptr;
                    }
                    if (wp->notify_status != ERROR_SUCCESS) {
                        // MARKED_FOR_DELETE / CLIENT_LAGGING or similar — the
                        // ServiceStatus is not trustworthy; re-resolve from
                        // scratch (-> absent path if truly gone).
                        arm_watch(*wp, emits, faults);
                        continue;
                    }
                    if (is_pending(wp->current_state)) {
                        // Transitional: HOLD (no compare), just re-arm the
                        // one-shot so the terminal state is still seen.
                        if (NotifyServiceStatusChangeW(wp->svc.get(), kNotifyMask, &wp->notify) !=
                            ERROR_SUCCESS)
                            arm_watch(*wp, emits, faults);
                        continue;
                    }
                    // Terminal: re-arm the one-shot FIRST (it is consumed on
                    // delivery — never leave the watch deaf while dispatching
                    // arbitrary consumer code), then map + edge-dedup.
                    const bool rearmed = NotifyServiceStatusChangeW(wp->svc.get(), kNotifyMask,
                                                                    &wp->notify) == ERROR_SUCCESS;
                    set_terminal(*wp, map_terminal(wp->current_state), emits);
                    if (!rearmed)
                        arm_watch(*wp, emits, faults);
                }
                if (!any) {
                    break; // converged — nothing fired this pass
                }
                if (pass == kMaxFiredScanPasses - 1) {
                    // Hit the cap with more still pending — self-wake so any
                    // straggler is picked up on the next outer-loop iteration
                    // instead of looping unbounded on this thread.
                    wake_signal();
                }
            }

            // Reap retiring watches: absorb any stale APC silently (no keys
            // left, so no consumer to notify — just clear the flag and free
            // the name buffer) and free the SvcWatch for real once quiescent
            // for kRetireGracePasses consecutive passes. This is what makes
            // the "don't free synchronously on removal" fix above safe
            // regardless of exactly when CloseServiceHandle's cancellation
            // takes effect — the object stays alive (just never re-armed)
            // until nothing has touched it for a few loop iterations.
            for (auto& rw : retiring_) {
                if (rw->fired) {
                    rw->fired = false;
                    if (rw->notify.pszServiceNames) {
                        LocalFree(rw->notify.pszServiceNames);
                        rw->notify.pszServiceNames = nullptr;
                    }
                    rw->retire_grace = kRetireGracePasses; // still live — reset the countdown
                } else if (rw->retire_grace > 0) {
                    --rw->retire_grace;
                }
            }
            retiring_.erase(std::remove_if(retiring_.begin(), retiring_.end(),
                                           [](const std::unique_ptr<SvcWatch>& rw) {
                                               return rw->retire_grace == 0 && !rw->fired;
                                           }),
                            retiring_.end());

            dispatch(emits, faults);
        }

        // Thread exit path: tear down every outstanding registration on THIS
        // thread (the registering thread — SERVICE_NOTIFYW/APC ownership).
        // Duplicated into both catch blocks below (not just here) so an
        // exception mid-loop can't skip it and leave stop()'s "already torn
        // down" assumption false (governance Gate-3 cpp-safety finding).
        for (auto& [name, wp] : svcs_)
            teardown_watch(*wp);
    } catch (const std::exception& e) {
        spdlog::error("spark_service: mechanism thread exception: {} — mechanism stopping",
                      e.what());
        for (auto& [name, wp] : svcs_)
            teardown_watch(*wp);
    } catch (...) {
        spdlog::error("spark_service: mechanism thread unknown exception — mechanism stopping");
        for (auto& [name, wp] : svcs_)
            teardown_watch(*wp);
    }

    std::mutex mu_; ///< guards ONLY pending_ + the start/stop/scm_ok_ flags
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    std::deque<Cmd> pending_;
    bool started_{false};
    std::atomic<bool> scm_ok_{false};
    /// Started, but the SCM / wake-event could not be acquired — every watch() will be
    /// refused. Published separately from scm_ok_ (which is also false pre-start) so
    /// stats() can report the mechanism as inert WITHOUT mu_, and so a never-started
    /// mechanism is not misreported as inert. An SCM-denied mechanism stays REGISTERED
    /// and would otherwise be indistinguishable from a healthy idle one on the wire
    /// (governance Gate-3 cross-platform / Gate-6 sre).
    std::atomic<bool> started_inert_{false};
    std::atomic<bool> stop_{false};
    std::thread thread_;
    yuzu::win::ScHandle scm_;
    detail::EventHandle wake_;

    // Mechanism-thread-confined (no lock): touched only from run(), and from
    // stop() after the thread has joined.
    std::unordered_map<std::wstring, std::unique_ptr<SvcWatch>> svcs_; ///< keyed by folded name
    std::unordered_map<std::string, std::wstring> key_svc_;           ///< spark key -> folded name
    /// Removed watches awaiting quiescence before real free — see the
    /// Cmd::Remove handling and the reap loop in run() for why a watch isn't
    /// freed synchronously on removal.
    std::vector<std::unique_ptr<SvcWatch>> retiring_;
};

} // namespace

std::unique_ptr<ISparkMechanism> make_service_mechanism() {
    return std::make_unique<WindowsServiceMechanism>();
}

} // namespace yuzu::agent

#else // ── macOS, or a Linux build without libsystemd: no mechanism ──────────

namespace yuzu::agent {

std::unique_ptr<ISparkMechanism> make_service_mechanism() {
    return nullptr; // no mechanism → SparkEngine rejects arm(Service)
}

} // namespace yuzu::agent

#endif
