/**
 * guard_systemd.cpp — see guard_systemd.hpp.
 *
 * Linux: a single watch thread opens the system D-Bus, Subscribes to the systemd
 * Manager, resolves the watched unit's object path (LoadUnit force-loads it so the
 * path is valid even when the unit is inactive), reads `ActiveState` (the initial
 * compare), and arms a PropertiesChanged match on the unit object. A poll loop over
 * { bus fd, stop eventfd } services the match: on each notification it re-reads
 * ActiveState and, on a TERMINAL state CHANGE, compares to the rule's desired state
 * and emits a GuardDrift. A bounded safety reconcile (and the absent re-poll) catch
 * a missed signal or the unit being removed / re-created — fully event-driven while
 * healthy, bounded-poll only while degraded (mirrors the Windows guard).
 *
 * v1 is OBSERVE ONLY: enforce-mode rules are detected + reported but NOT remediated
 * (no MaskUnit / StopUnit). Enforcement is a separate, governance-gated change.
 *
 * The pure state-mapping helpers (parse_active_state / systemd_is_compliant / …) are
 * compiled on EVERY platform so they are unit-testable off Linux against captured
 * ActiveState strings (mirrors dex_observer.hpp's extract_named_data). Only the
 * sd-bus engine is Linux-gated; off Linux the guard is a no-op (start() → false).
 */

#include <yuzu/agent/guard_systemd.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::agent {

// ── Pure state-mapping helpers (compiled on every platform) ──────────────────

SystemdState parse_active_state(std::string_view s) {
    if (s == "active")
        return SystemdState::Active;
    if (s == "reloading")
        return SystemdState::Reloading;
    if (s == "inactive")
        return SystemdState::Inactive;
    if (s == "failed")
        return SystemdState::Failed;
    if (s == "activating")
        return SystemdState::Activating;
    if (s == "deactivating")
        return SystemdState::Deactivating;
    if (s == "maintenance")
        return SystemdState::Maintenance;
    return SystemdState::Unknown;
}

bool systemd_state_is_transitional(SystemdState s) {
    switch (s) {
    case SystemdState::Reloading:
    case SystemdState::Activating:
    case SystemdState::Deactivating:
    case SystemdState::Maintenance:
    case SystemdState::Unknown: // a state we do not understand is held, never drifted
        return true;
    case SystemdState::Active:
    case SystemdState::Inactive:
    case SystemdState::Failed:
    case SystemdState::Absent:
        return false;
    }
    return true;
}

bool systemd_is_compliant(ServiceGuard::Desired want, SystemdState got) {
    if (want == ServiceGuard::Desired::Running)
        return got == SystemdState::Active;
    // Desired::Stopped — anything not active counts as stopped; a failed or absent
    // unit is, definitionally, not running.
    return got == SystemdState::Inactive || got == SystemdState::Failed ||
           got == SystemdState::Absent;
}

std::string_view systemd_state_token(SystemdState s) {
    switch (s) {
    case SystemdState::Active:       return "running";
    case SystemdState::Inactive:     return "stopped";
    case SystemdState::Failed:       return "failed";
    case SystemdState::Absent:       return "absent";
    case SystemdState::Reloading:    return "reloading";
    case SystemdState::Activating:   return "activating";
    case SystemdState::Deactivating: return "deactivating";
    case SystemdState::Maintenance:  return "maintenance";
    case SystemdState::Unknown:      return "unknown";
    }
    return "unknown";
}

std::string normalize_unit_name(std::string_view unit) {
    std::string out(unit);
    if (out.find('.') == std::string::npos)
        out += ".service";
    return out;
}

bool valid_unit_name(std::string_view unit) {
    if (unit.empty() || unit.size() > 256)
        return false;
    for (char c : unit) {
        const auto uc = static_cast<unsigned char>(c);
        if (!std::isalnum(uc) && c != '.' && c != '_' && c != '-' && c != '@')
            return false;
    }
    return true;
}

std::unique_ptr<IGuard> make_service_guard(ServiceGuard::Config cfg, GuardSink sink) {
#if defined(__linux__)
    return std::make_unique<SystemdServiceGuard>(std::move(cfg), std::move(sink));
#else
    return std::make_unique<ServiceGuard>(std::move(cfg), std::move(sink));
#endif
}

} // namespace yuzu::agent

#if defined(__linux__)

#include <systemd/sd-bus.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib> // free
#include <cstring> // std::strerror
#include <ctime>
#include <optional>

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace yuzu::agent {
namespace {

constexpr const char* kDest      = "org.freedesktop.systemd1";
constexpr const char* kMgrPath   = "/org/freedesktop/systemd1";
constexpr const char* kMgrIface  = "org.freedesktop.systemd1.Manager";
constexpr const char* kUnitIface = "org.freedesktop.systemd1.Unit";
constexpr const char* kPropsIface = "org.freedesktop.DBus.Properties";

// Degraded re-poll cadence while the unit is absent (no object to match a signal
// on) — mirrors the Windows guard's kAbsentRetryMs. The healthy watch is fully
// event-driven via PropertiesChanged; the longer backstop only guards against a
// missed signal or the unit object being destroyed/re-created.
constexpr std::uint64_t kAbsentRetryMs = 30000;
constexpr std::uint64_t kHealthyReconcileMs = 60000;

std::uint64_t monotonic_us() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000ull +
           static_cast<std::uint64_t>(ts.tv_nsec) / 1000ull;
}

// PropertiesChanged match callback. Runs synchronously inside sd_bus_process() on
// the watch thread (never concurrently), so it just flips a plain bool the loop
// drains — the loop re-reads ActiveState rather than parsing the changed-property
// set, which is both simpler and robust to PropertiesChanged batching.
int on_props_changed(sd_bus_message* /*m*/, void* userdata, sd_bus_error* /*ret*/) {
    if (userdata)
        *static_cast<bool*>(userdata) = true;
    return 0;
}

} // namespace

SystemdServiceGuard::SystemdServiceGuard(Config cfg, Sink sink)
    : cfg_(std::move(cfg)), sink_(std::move(sink)) {}

SystemdServiceGuard::~SystemdServiceGuard() { stop(); }

bool SystemdServiceGuard::start() {
    if (!valid_unit_name(cfg_.service_name)) {
        spdlog::warn("Guardian SystemdServiceGuard[{}]: invalid unit name '{}'", cfg_.rule_id,
                     cfg_.service_name);
        return false;
    }
    sd_bus* bus = nullptr;
    int r = sd_bus_open_system(&bus);
    if (r < 0 || !bus) {
        // No system bus → not a systemd host (or no access). v1 degrades to
        // unarmed (detect-only requires the /proc fallback, a later slice).
        spdlog::warn("Guardian SystemdServiceGuard[{}]: system bus unavailable ({}) — unit '{}' "
                     "unwatched (non-systemd host?)",
                     cfg_.rule_id, (r < 0 ? std::strerror(-r) : "no bus"), cfg_.service_name);
        if (bus)
            sd_bus_unref(bus);
        return false;
    }
    int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (efd < 0) {
        sd_bus_unref(bus);
        return false;
    }
    bus_ = bus;
    wake_fd_ = efd;
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
    return true;
}

void SystemdServiceGuard::stop() {
    if (thread_.joinable()) {
        stop_.store(true, std::memory_order_release);
        if (wake_fd_ >= 0) {
            const std::uint64_t one = 1;
            ssize_t w = ::write(wake_fd_, &one, sizeof(one));
            (void)w; // wake is best-effort; the thread also re-checks stop_ each iteration
        }
        thread_.join();
    }
    if (bus_) {
        sd_bus_flush(static_cast<sd_bus*>(bus_));
        sd_bus_unref(static_cast<sd_bus*>(bus_));
        bus_ = nullptr;
    }
    if (wake_fd_ >= 0) {
        ::close(wake_fd_);
        wake_fd_ = -1;
    }
}

void SystemdServiceGuard::run() try {
    auto* bus = static_cast<sd_bus*>(bus_);
    const std::string unit = normalize_unit_name(cfg_.service_name);
    const char* expected_token = (cfg_.desired == Desired::Running) ? "running" : "stopped";

    if (cfg_.enforce)
        spdlog::warn("Guardian SystemdServiceGuard[{}]: enforce-mode not yet supported on Linux — "
                     "observing unit '{}' only (drift reported, not remediated)",
                     cfg_.rule_id, unit);

    // Best-effort Subscribe so the Manager emits unit signals to us. Not fatal if
    // it fails — PropertiesChanged on the unit object still works without it on most
    // systemd versions; we just lose the Manager-level UnitNew/Removed stream (the
    // bounded reconcile backstop covers add/remove anyway).
    {
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_message* reply = nullptr;
        if (sd_bus_call_method(bus, kDest, kMgrPath, kMgrIface, "Subscribe", &err, &reply, "") < 0)
            spdlog::debug("Guardian SystemdServiceGuard[{}]: Subscribe failed: {}", cfg_.rule_id,
                          err.message ? err.message : "(none)");
        if (reply)
            sd_bus_message_unref(reply);
        sd_bus_error_free(&err);
    }

    std::string unit_path; // resolved object path of the watched unit
    bool dirty = false;    // set by on_props_changed; drained each loop iteration

    // Sink-debounce (H3 / #1209) + change-dedup: only this thread touches these.
    std::optional<std::chrono::steady_clock::time_point> last_emit;
    std::uint64_t suppressed = 0;
    SystemdState last_terminal = SystemdState::Unknown; // last terminal state acted on

    auto emit = [&](SystemdState got) {
        if (systemd_state_is_transitional(got))
            return;                  // hold on transitional / not-understood states
        if (got == last_terminal)
            return;                  // no change since last terminal observation (incl. backstop)
        last_terminal = got;
        if (systemd_is_compliant(cfg_.desired, got))
            return;                  // compliant edge — drift-only sink, mirrors ServiceGuard
        ServiceDrift d;
        d.guard_type = "service";
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.detected_value = std::string(systemd_state_token(got));
        d.expected_value = expected_token;
        d.detection_latency_us = 0; // v1: not measured (sd-bus gives no kernel event time)
        const auto now = std::chrono::steady_clock::now();
        if (last_emit &&
            (now - *last_emit) < std::chrono::milliseconds(cfg_.event_debounce_ms)) {
            ++suppressed;
            return;
        }
        d.collapsed_count = suppressed;
        suppressed = 0;
        last_emit = now;
        spdlog::info("Guardian SystemdServiceGuard[{}]: drift unit '{}' detected={} expected={}",
                     cfg_.rule_id, unit, d.detected_value, expected_token);
        if (sink_)
            sink_(d);
    };

    // LoadUnit force-loads the unit and returns its object path (valid even when
    // inactive). Failure (NoSuchUnit / LoadFailed) → the unit is absent.
    auto resolve_path = [&]() -> bool {
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_message* reply = nullptr;
        bool ok = false;
        int r = sd_bus_call_method(bus, kDest, kMgrPath, kMgrIface, "LoadUnit", &err, &reply, "s",
                                   unit.c_str());
        if (r >= 0 && reply) {
            const char* p = nullptr;
            if (sd_bus_message_read(reply, "o", &p) >= 0 && p && *p) {
                unit_path = p;
                ok = true;
            }
        } else {
            spdlog::debug("Guardian SystemdServiceGuard[{}]: LoadUnit '{}' failed: {}", cfg_.rule_id,
                          unit, err.message ? err.message : "(none)");
        }
        if (reply)
            sd_bus_message_unref(reply);
        sd_bus_error_free(&err);
        return ok;
    };

    auto read_state = [&]() -> SystemdState {
        if (unit_path.empty())
            return SystemdState::Absent;
        sd_bus_error err = SD_BUS_ERROR_NULL;
        char* s = nullptr;
        SystemdState st = SystemdState::Absent;
        int r = sd_bus_get_property_string(bus, kDest, unit_path.c_str(), kUnitIface, "ActiveState",
                                           &err, &s);
        if (r >= 0 && s)
            st = parse_active_state(s);
        if (s)
            free(s);
        sd_bus_error_free(&err);
        return st;
    };

    sd_bus_slot* match_slot = nullptr;

    // Re-resolve from scratch: drop the old match, LoadUnit, arm a PropertiesChanged
    // match on the (possibly new) object path, and do the compare. Returns the
    // backstop cadence to use until the next forced reconcile.
    auto reconcile = [&]() -> std::uint64_t {
        if (match_slot) {
            sd_bus_slot_unref(match_slot);
            match_slot = nullptr;
        }
        if (!resolve_path()) {
            unit_path.clear();
            emit(SystemdState::Absent);
            return kAbsentRetryMs;
        }
        int r = sd_bus_match_signal(bus, &match_slot, kDest, unit_path.c_str(), kPropsIface,
                                    "PropertiesChanged", &on_props_changed, &dirty);
        if (r < 0) {
            spdlog::warn("Guardian SystemdServiceGuard[{}]: match arm failed for '{}': {}",
                         cfg_.rule_id, unit, std::strerror(-r));
            emit(read_state());
            return kAbsentRetryMs;
        }
        emit(read_state()); // initial / re-resolved compare
        return kHealthyReconcileMs;
    };

    spdlog::info("Guardian SystemdServiceGuard[{}]: watching unit '{}' (expect {})", cfg_.rule_id,
                 unit, expected_token);

    std::uint64_t backstop_ms = reconcile();
    auto next_backstop = std::chrono::steady_clock::now() + std::chrono::milliseconds(backstop_ms);
    const int bus_fd = sd_bus_get_fd(bus);

    while (!stop_.load(std::memory_order_acquire)) {
        // 1) Drain all queued bus messages (dispatches the match → may set dirty).
        for (;;) {
            int r = sd_bus_process(bus, nullptr);
            if (r < 0) {
                spdlog::warn("Guardian SystemdServiceGuard[{}]: sd_bus_process: {}", cfg_.rule_id,
                             std::strerror(-r));
                break;
            }
            if (stop_.load(std::memory_order_acquire) || r == 0)
                break;
        }
        if (stop_.load(std::memory_order_acquire))
            break;

        // 2) A PropertiesChanged fired → re-read ActiveState and compare.
        if (dirty) {
            dirty = false;
            emit(read_state());
        }

        // 3) Compute the poll timeout: until the next backstop, capped by sd-bus's
        //    own next-operation deadline (an ABSOLUTE CLOCK_MONOTONIC us value).
        const auto now = std::chrono::steady_clock::now();
        long long timeout_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(next_backstop - now).count();
        if (timeout_ms < 0)
            timeout_ms = 0;
        std::uint64_t bus_to_us = UINT64_MAX;
        if (sd_bus_get_timeout(bus, &bus_to_us) >= 0 && bus_to_us != UINT64_MAX) {
            const std::uint64_t now_us = monotonic_us();
            const long long bus_ms =
                bus_to_us > now_us ? static_cast<long long>((bus_to_us - now_us) / 1000) : 0;
            if (bus_ms < timeout_ms)
                timeout_ms = bus_ms;
        }

        struct pollfd fds[2];
        fds[0].fd = bus_fd;
        fds[0].events = static_cast<short>(sd_bus_get_events(bus));
        fds[0].revents = 0;
        fds[1].fd = wake_fd_;
        fds[1].events = POLLIN;
        fds[1].revents = 0;
        int pr = ::poll(fds, 2, static_cast<int>(timeout_ms));
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            spdlog::warn("Guardian SystemdServiceGuard[{}]: poll: {}", cfg_.rule_id,
                         std::strerror(errno));
            break;
        }
        if (fds[1].revents & POLLIN)
            break; // stop() signalled

        if (std::chrono::steady_clock::now() >= next_backstop) {
            backstop_ms = reconcile();
            next_backstop =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(backstop_ms);
        }
        // Otherwise the bus fd is readable → loop; sd_bus_process drains it.
    }

    if (match_slot)
        sd_bus_slot_unref(match_slot);
    // bus_ is unref'd in stop() after the join (single owner of the handle there).
} catch (const std::exception& e) {
    spdlog::error("Guardian SystemdServiceGuard[{}]: watch thread exception: {} — watch stopping",
                  cfg_.rule_id, e.what());
} catch (...) {
    spdlog::error("Guardian SystemdServiceGuard[{}]: watch thread unknown exception — stopping",
                  cfg_.rule_id);
}

} // namespace yuzu::agent

#else // ── Non-Linux: no-op (no sd-bus) ─────────────────────────────────────────

namespace yuzu::agent {

SystemdServiceGuard::SystemdServiceGuard(Config cfg, Sink sink)
    : cfg_(std::move(cfg)), sink_(std::move(sink)) {}
SystemdServiceGuard::~SystemdServiceGuard() {}
bool SystemdServiceGuard::start() { return false; }
void SystemdServiceGuard::stop() {}
void SystemdServiceGuard::run() {}

} // namespace yuzu::agent

#endif
