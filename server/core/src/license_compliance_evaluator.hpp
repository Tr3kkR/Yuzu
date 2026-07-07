#pragma once

/// @file license_compliance_evaluator.hpp
/// The SLE compliance evaluator (ADR-0024 Decisions 6/7/8): a background
/// thread that periodically derives the fleet licence-posture rollup and
/// raises the deduplicated `software_license.expiring` /
/// `software_license.expired` events.
///
/// One cycle (`tick()`) runs three passes:
///   1. MATCHER — joins the detected (product, vendor) pairs and the
///      installed-software catalogue titles against the product registry's
///      candidate set (`product_normalize::match_product`), minting registry
///      rows for newly detected products (births) and refreshing the alias
///      links EVERY cycle (roadmap R7 — soft keys re-resolve; matcher
///      improvements self-heal).
///   2. ROLLUP — aggregates the store's grouped licence-row inputs into
///      per-product `LicensePostureRow`s (per-effective-state counts via the
///      Decision 7 lapse rule against ONE cycle-wide `now`), joins
///      `install_count` from the catalogue through the just-derived alias
///      map, keeps the honest `''` unmatched bucket, and atomically replaces
///      the rollup (store keep-last-good).
///   3. ALERTS — evaluates the two per-product conditions against the
///      durable `license_alert_state` dedup rows: worsening-bucket-only
///      escalation (30/14/7/1 days), 7-day re-arm, hold-down, and the G-3
///      bounded first-evaluation burst. Over-deployment deliberately does
///      NOT alert in v1 (roadmap R11) — the kind vocabulary stays closed.
///
/// FAIL-CLOSED INPUTS (the F4 rule): the posture rollup is a FULL REPLACE,
/// so a degrade on ANY authoritative input read — or a failed birth write —
/// aborts the cycle BEFORE the replace (keep-last-good; the as-of stamp
/// visibly ages; `runs_total{outcome="degraded"}` counts it). A partial
/// input must never full-replace the posture into a silently smaller one.
/// Likewise a degraded `alert_state` read suppresses that condition — a
/// degrade must never read as "never fired" (it would re-fire every cycle).
///
/// Lifecycle mirrors `SoftwareCatalogRollup` (idempotent `start()`,
/// signal+join `stop()`, dtor stops, one immediate tick, completion-spaced
/// cadence, catch-all around the tick). DIVERGENCE from that clone target:
/// all I/O goes through injected `Deps` providers and the clock through
/// `NowFn` (the `PreflightRunner` seam), and the cycle body is the public
/// `tick()` — the whole state machine is unit-testable without Postgres and
/// without the thread. Everything that *decides* is a pure free function.

#include "software_inventory_store.hpp"
#include "software_licensing_store.hpp"
#include "product_registry_store.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// One emission handed to the `on_alert` sink. server.cpp's closure builds
/// the operator notification and the §3.4 webhook/offload payload from it
/// (dual-sink, the DexAlertRouter precedent).
struct SleAlert {
    std::string kind;        ///< "expiring" | "expired" (the closed store vocabulary)
    std::string product_key; ///< registry norm_key (the '' bucket never alerts)
    std::string vendor;
    std::string title;
    std::int64_t device_count{0};
    std::int64_t next_expiry_at{0};
    std::int64_t days_left{0}; ///< ceiling days to next_expiry_at; 0 for "expired"
    std::int64_t bucket{0};    ///< 30/14/7/1 for "expiring"; 0 for "expired"
};

/// The event type fired on the webhook/offload sinks:
/// "software_license.expiring" | "software_license.expired".
std::string sle_alert_event_type(std::string_view kind);

/// The §3.4 external payload contract, exactly these keys:
/// {event, product_key, vendor, title, device_count, next_expiry_at,
///  days_left, bucket}. Pure; pinned by unit test.
nlohmann::json sle_alert_payload(const SleAlert& a);

/// PURE bucket derivation for the "expiring" condition: no bucket when
/// `next_expiry_at <= now` (expired's territory) or when more than
/// `kExpiryAlertBuckets.front()` (30) days remain; otherwise the smallest
/// threshold >= the CEILING days-left (<=1d -> 1, <=7d -> 7, <=14d -> 14,
/// <=30d -> 30). Worse == smaller.
std::optional<int> sle_expiring_bucket(std::int64_t next_expiry_at, std::int64_t now);

/// PURE per-(product_key, kind) dedup decision (ADR-0024 Decision 8).
/// Fires iff any of:
///   - no prior state row -> `first_eval` (the G-3 bounded first-evaluation
///     burst: once per product per kind on a fresh estate, and again after
///     dedup-state loss),
///   - `bucket < prior->bucket` -> `worsened` (escalation down 30->14->7->1),
///   - `now - prior->last_fired_at >= kRearmSecs` -> `rearmed` (persistence),
///   - else `holddown`.
/// A fingerprint change alone never fires: a min-expiry shift LATER (renewal
/// / near row dropping out) would otherwise spam a fresh instance; a shift
/// EARLIER lands in a worse bucket and fires via `worsened`; a stale row
/// re-fires via `rearmed`. Because state rows persist across clears, a
/// clear-then-re-assert inside the re-arm window is suppressed and
/// persistence past it re-fires — exactly the Decision 8 semantics.
struct SleAlertDecision {
    bool fire{false};
    enum class Reason { first_eval, worsened, rearmed, holddown } reason{Reason::holddown};
};
SleAlertDecision sle_decide_alert(const std::optional<LicenseAlertState>& prior,
                                  std::int64_t bucket, std::int64_t now);

class LicenseComplianceEvaluator {
public:
    /// Injectable clock (epoch SECONDS — the store columns' unit). Empty =
    /// system clock. The one `now` drawn per cycle is simultaneously the
    /// rollup `refreshed_at`, the lapse rule's server-now, and the alert
    /// clock — one consistent as-of (roadmap G-4).
    using NowFn = std::function<std::int64_t()>;

    /// All I/O the evaluator performs, injected so the state machine tests
    /// pure. The authoritative reads return nullopt on degrade — any of them
    /// degrading aborts the cycle (F4). The registry writes are fail-soft in
    /// the store; the ABORT policy on a failed birth is the evaluator's (a
    /// birthed product misfiled into '' would be a wrong rollup, and a write
    /// failing mid-cycle almost certainly means PG trouble anyway).
    struct Deps {
        std::function<std::optional<std::vector<ProductRow>>()> list_products;
        std::function<std::optional<std::vector<DetectedProduct>>()> distinct_products;
        std::function<std::optional<LicensePostureInputs>()> posture_inputs;
        std::function<std::optional<std::vector<SoftwareCatalogRow>>()> software_catalog;
        std::function<std::optional<std::int64_t>(
            std::string_view norm_key, std::string_view vendor, std::string_view title,
            std::string_view edition, std::string_view platform)>
            upsert_product;
        std::function<bool(std::string_view source, std::string_view raw_name,
                           std::string_view raw_publisher, std::int64_t product_id,
                           std::string_view method, double confidence)>
            upsert_alias;
        std::function<bool(const std::vector<LicensePostureRow>&, std::int64_t)>
            replace_posture_rollup;
        std::function<std::expected<std::optional<LicenseAlertState>, LicensingReadError>(
            std::string_view product_key, std::string_view kind)>
            alert_state;
        std::function<bool(std::string_view product_key, std::string_view kind,
                           std::string_view fingerprint, std::int64_t bucket,
                           std::int64_t last_fired_at)>
            upsert_alert_state;
        /// Dual-sink emission closure (server.cpp). Called OUTSIDE any lock,
        /// inside the evaluator's own try/catch — a throwing sink is counted
        /// (`..._alert_delivery_failed_total`) and never kills the cycle.
        std::function<void(const SleAlert&)> on_alert;
        NowFn now_fn;                         ///< empty = system clock
        yuzu::MetricsRegistry* metrics{nullptr}; ///< borrowed/optional
        std::chrono::seconds interval{3600};  ///< completion-to-start spacing
    };

    explicit LicenseComplianceEvaluator(Deps deps);
    ~LicenseComplianceEvaluator();

    LicenseComplianceEvaluator(const LicenseComplianceEvaluator&) = delete;
    LicenseComplianceEvaluator& operator=(const LicenseComplianceEvaluator&) = delete;

    /// Spawn the background thread (idempotent — a second call is a no-op).
    void start();
    /// Signal stop and join (idempotent; also called by the destructor).
    void stop();

    enum class TickOutcome {
        success,  ///< rollup replaced; alert pass ran
        degraded, ///< an authoritative input degraded (or a birth write
                  ///< failed) — cycle skipped BEFORE the replace (F4
                  ///< keep-last-good; the as-of stamp ages)
        error,    ///< the rollup replace itself failed — alert pass skipped
                  ///< (alerting on rows the surface never got would
                  ///< desynchronise alerts from the page)
    };

    /// Run ONE full cycle (matcher -> rollup -> alert pass). Public on
    /// purpose: it is both the thread body and the test seam — tests drive
    /// explicit ticks against fake Deps and an injected clock.
    TickOutcome tick();

private:
    void run();

    Deps d_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

} // namespace yuzu::server
