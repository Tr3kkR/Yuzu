#pragma once

/**
 * spark.hpp — the Spark contract: the platform's use-case-agnostic detection
 * primitive (ADR-0021 Decision 1).
 *
 * A Spark is a type plus parameters describing a device condition to watch
 * (interval elapsed, agent startup, disk threshold crossing, file change,
 * service state change, registry change). Consumers (Guardian, DEX, Reflex)
 * subscribe to a SparkSpec and receive SparkEvents; they own the MEANING of
 * those events — a Spark never carries an assertion, an observation type, or
 * a Reaction. "Armed" means the SparkEngine is running a watcher for the spec;
 * consumers never see watcher instances (spark_engine.hpp).
 *
 * Two subscription tiers (ADR-0021 Decision 3):
 *   - Queued  — per-consumer queue + dispatch thread; consumer code NEVER runs
 *               on a watcher thread, so a blocked consumer cannot stall
 *               detection or a sibling consumer.
 *   - Inline  — synchronous on the watcher thread. µs-MEDIAN dispatch, NOT a
 *               hard worst-case bound (owner decision 2026-07-06 on the
 *               stage0-windows-spikes §1b probe: p99 can reach 100s of µs and
 *               a scheduler-quantum ~10ms outlier is possible on a shared
 *               pool). Enforce-class handlers only — non-blocking, never a
 *               plugin call. Core-internal: this API is not reachable from the
 *               plugin ABI, and Stage 2 narrows the handler's capability
 *               surface to the enforce context.
 *
 * Proto-free and windows.h-free by design (the guard.hpp rationale): this
 * header is the vocabulary shared by the engine, every consumer, and the
 * tests, so it must be includable anywhere.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <chrono>
#include <cstdint>
#include <string>
#include <variant>

namespace yuzu::agent {

// ── Spark types ───────────────────────────────────────────────────────────────

/// The detection mechanisms the platform offers. This is the full content-plane
/// vocabulary (stage0-trigger-inventory.md): interval / file_change /
/// service_status / registry_change / agent_startup, plus the DEX-originated
/// disk threshold. Which types are armable in a given build/slice is the
/// engine's concern (spark_engine.hpp), not the vocabulary's.
enum class SparkType {
    Interval, ///< fires every interval_ms
    Startup,  ///< fires once, at engine start (or at arm time if already started)
    Disk,     ///< threshold poll-and-latch on a volume/path — breach + recovery edges
    File,     ///< file/directory change (kernel-notified; mechanism PR 1b)
    Service,  ///< service/unit run-state change (multiplexed; mechanism PR 1c)
    Registry, ///< Windows registry key change (wait-pool; mechanism PR 1b)
};

/// Stable token for logs, keys, and (later) the content plane.
[[nodiscard]] constexpr const char* spark_type_token(SparkType t) noexcept {
    switch (t) {
    case SparkType::Interval: return "interval";
    case SparkType::Startup:  return "startup";
    case SparkType::Disk:     return "disk";
    case SparkType::File:     return "file";
    case SparkType::Service:  return "service";
    case SparkType::Registry: return "registry";
    }
    return "unknown";
}

// ── Per-type parameters ───────────────────────────────────────────────────────

struct IntervalSparkParams {
    /// Fire cadence. The engine floors this (default 30s — the TriggerEngine
    /// minimum, lowerable only via the test seam) rather than rejecting, so a
    /// too-eager author degrades gracefully.
    std::uint64_t interval_ms{0};
    bool operator==(const IntervalSparkParams&) const = default;
};

struct StartupSparkParams {
    bool operator==(const StartupSparkParams&) const = default;
};

struct DiskSparkParams {
    std::string path;                      ///< volume root or any path on the filesystem to watch
    std::uint32_t used_pct_threshold{90};  ///< bad when used% >= this (1..100)
    std::uint64_t min_free_bytes{5ull * 1024 * 1024 * 1024}; ///< bad when free < this; 0 disables
    std::uint64_t poll_ms{600'000};        ///< poll cadence (floored like interval_ms)
    bool operator==(const DiskSparkParams&) const = default;
};

struct FileSparkParams {
    std::string path; ///< target file (watching mechanism lands in PR 1b)
    bool operator==(const FileSparkParams&) const = default;
};

struct ServiceSparkParams {
    std::string service_name; ///< SCM service / systemd unit name (mechanism PR 1c)
    bool operator==(const ServiceSparkParams&) const = default;
};

struct RegistrySparkParams {
    std::string hive; ///< "HKLM" | "HKCU" | "HKCR" | "HKU"
    std::string key;  ///< subkey path (mechanism PR 1b)
    bool operator==(const RegistrySparkParams&) const = default;
};

using SparkParams = std::variant<IntervalSparkParams, StartupSparkParams, DiskSparkParams,
                                 FileSparkParams, ServiceSparkParams, RegistrySparkParams>;

/// An authored detection spec: what to watch. Two specs with equal (type, params)
/// are the SAME armed spark — the engine dedups arming across consumers
/// (N subscriptions, 1 watcher).
struct SparkSpec {
    SparkType type{SparkType::Interval};
    SparkParams params{IntervalSparkParams{}};
    bool operator==(const SparkSpec&) const = default;
};

/// Canonical identity of an armed spark — deterministic over (type, params).
/// This is the dedup key and the event correlation handle consumers see.
[[nodiscard]] YUZU_EXPORT std::string spark_key(const SparkSpec& spec);

// ── Event payloads ────────────────────────────────────────────────────────────

/// One disk capacity reading. `valid == false` = the read failed (path gone,
/// permission, device error) — a failed reading must never read as a full OR a
/// healthy disk (gov UP-5).
struct DiskReading {
    bool valid{false};
    std::uint64_t total_bytes{0};
    std::uint64_t free_bytes{0};
    bool operator==(const DiskReading&) const = default;
};

/// Which latch edge a disk poll crossed. Breach = transition INTO the bad
/// state (emit once, suppressed while it persists); Recovery = a VALID reading
/// showed healthy again (re-arms the latch). Consumers own the meaning — DEX
/// maps Breach to `storage.low`; a Reflex episode opens on Breach and closes
/// on Recovery (ADR-0021 Decision 4 / Stage 3).
enum class DiskEdge { Breach, Recovery };

struct DiskSparkData {
    DiskReading reading;
    DiskEdge edge{DiskEdge::Breach};
    bool operator==(const DiskSparkData&) const = default;
};

/// Resolved run state of a watched service/unit — the TERMINAL vocabulary only.
/// Mapping (mirrors guard_systemd / guard_service, the governed precedents):
///   Linux  : active → Running; inactive / failed / absent(not-loaded) → Stopped;
///            activating / deactivating / reloading / maintenance / unknown →
///            TRANSITIONAL — HELD, never emitted (see rationale below).
///   Windows: SERVICE_RUNNING → Running; SERVICE_STOPPED / absent / deleted →
///            Stopped; SERVICE_PAUSED → Paused (a TERMINAL SCM state — the guard
///            compares and remediates on it, so the raw primitive must surface it
///            or a consumer goes blind to paused drift); *_PENDING →
///            TRANSITIONAL — HELD.
/// Transitional states are held, not emitted: a consumer can neither assert over
/// nor enforce against a mid-transition state (the guards hold on exactly these),
/// and emitting them would make every stop/start a multi-event flap each consumer
/// must re-filter. The enum is deliberately open — a Transitional member can be
/// added later without breaking the wire tokens below.
enum class ServiceRunState : std::uint8_t {
    Running,
    Stopped, ///< includes failed (Linux) and absent/deleted (both platforms)
    Paused,  ///< Windows-only terminal state; never produced on Linux
};

/// Stable token for logs and (later) the content plane.
[[nodiscard]] constexpr const char* service_run_state_token(ServiceRunState s) noexcept {
    switch (s) {
    case ServiceRunState::Running: return "running";
    case ServiceRunState::Stopped: return "stopped";
    case ServiceRunState::Paused:  return "paused";
    }
    return "unknown";
}

/// Event payload for a Service spark: the resolved terminal state AFTER the
/// change. Unlike File/Registry (monostate — consumer re-reads), the service
/// spark carries state because a consumer has no independent read primitive
/// that doesn't duplicate the mechanism's own sd-bus/SCM connection — the exact
/// resource duplication this mechanism exists to remove. Emitted once on
/// successful watch-arm (the initial resolved state) and thereafter only on
/// terminal-state edges; transitional states never emit and never move the
/// edge-dedup baseline.
struct ServiceSparkData {
    ServiceRunState state{ServiceRunState::Stopped};
    bool operator==(const ServiceSparkData&) const = default;
};

/// Type-specific event facts. Interval/Startup (and the File/Registry
/// change-signal types) carry no payload — the event itself is the fact;
/// consumers re-read whatever state they assert over. Service is the one
/// event-driven type that DOES carry a payload (ServiceSparkData) — see its
/// doc comment for why.
using SparkData = std::variant<std::monostate, DiskSparkData, ServiceSparkData>;

/// What a consumer receives when an armed spark fires.
struct SparkEvent {
    std::string key;                          ///< spark_key() of the armed spec
    SparkType type{SparkType::Interval};
    std::uint64_t seq{0};                     ///< per-armed-spark, monotonically increasing
    std::chrono::system_clock::time_point at; ///< wall-clock fire time
    SparkData data{};
};

// ── Subscription tiers ────────────────────────────────────────────────────────

enum class SparkTier {
    Inline, ///< synchronous on the watcher thread — enforce-class only (see header comment)
    Queued, ///< per-consumer queue + thread — everything else
};

} // namespace yuzu::agent
