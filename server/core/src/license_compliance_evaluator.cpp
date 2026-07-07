/// @file license_compliance_evaluator.cpp
/// Implementation of the SLE compliance evaluator. See the header for the
/// pass structure, the F4 fail-closed input rule, and the Decision 8 alert
/// semantics.

#include "license_compliance_evaluator.hpp"

#include "product_normalize.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <exception>
#include <map>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

std::int64_t system_now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// The alias `method` vocabulary (product_registry_store's ProductAliasRow).
const char* tier_name(MatchTier t) {
    switch (t) {
    case MatchTier::exact_norm:
        return "exact_norm";
    case MatchTier::title_vendor:
        return "title_vendor";
    case MatchTier::token_set:
        return "token_set";
    case MatchTier::birth:
        return "birth";
    }
    return "birth";
}

/// Map key for a raw (product, vendor) pair — 0x1f can appear in neither
/// (the ingest seam's scrub strips control bytes).
std::string pair_key(std::string_view product, std::string_view vendor) {
    std::string k;
    k.reserve(product.size() + 1 + vendor.size());
    k.append(product);
    k.push_back('\x1f');
    k.append(vendor);
    return k;
}

/// Ceiling days from `now` to `at` (both epoch seconds; caller guarantees
/// `at > now`).
std::int64_t ceil_days(std::int64_t at, std::int64_t now) {
    return (at - now + 86399) / 86400;
}

} // namespace

std::string sle_alert_event_type(std::string_view kind) {
    return std::string("software_license.") + (kind == "expired" ? "expired" : "expiring");
}

nlohmann::json sle_alert_payload(const SleAlert& a) {
    // The §3.4 external contract — exactly these keys. (nlohmann serialises
    // keys alphabetically; consumers key on names, not positions.)
    return nlohmann::json{
        {"event", sle_alert_event_type(a.kind)},
        {"product_key", a.product_key},
        {"vendor", a.vendor},
        {"title", a.title},
        {"device_count", a.device_count},
        {"next_expiry_at", a.next_expiry_at},
        {"days_left", a.days_left},
        {"bucket", a.bucket},
    };
}

std::optional<int> sle_expiring_bucket(std::int64_t next_expiry_at, std::int64_t now) {
    if (next_expiry_at <= now)
        return std::nullopt; // expired's territory, not "expiring"
    const std::int64_t days = ceil_days(next_expiry_at, now);
    if (days > kExpiryAlertBuckets.front())
        return std::nullopt;
    // Smallest threshold >= days-left (buckets are ordered 30/14/7/1).
    int chosen = kExpiryAlertBuckets.front();
    for (const int b : kExpiryAlertBuckets) {
        if (days <= b)
            chosen = b;
    }
    return chosen;
}

SleAlertDecision sle_decide_alert(const std::optional<LicenseAlertState>& prior,
                                  std::int64_t bucket, std::int64_t now) {
    using Reason = SleAlertDecision::Reason;
    if (!prior)
        return {true, Reason::first_eval}; // G-3 bounded first-evaluation burst
    if (bucket < prior->bucket)
        return {true, Reason::worsened}; // escalation down 30 -> 14 -> 7 -> 1
    if (now - prior->last_fired_at >= kRearmSecs)
        return {true, Reason::rearmed}; // persistence past the re-arm window
    return {false, Reason::holddown};
}

LicenseComplianceEvaluator::LicenseComplianceEvaluator(Deps deps) : d_(std::move(deps)) {
    if (d_.interval <= std::chrono::seconds{0})
        d_.interval = std::chrono::seconds{3600};
}

LicenseComplianceEvaluator::~LicenseComplianceEvaluator() { stop(); }

void LicenseComplianceEvaluator::start() {
    if (thread_.joinable())
        return; // already started
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
}

void LicenseComplianceEvaluator::stop() {
    stop_.store(true, std::memory_order_release);
    if (thread_.joinable())
        thread_.join();
}

LicenseComplianceEvaluator::TickOutcome LicenseComplianceEvaluator::tick() {
    // ONE now per cycle: the rollup as-of, the lapse rule's server-now, and
    // the alert clock stay mutually consistent (roadmap G-4).
    const std::int64_t now = d_.now_fn ? d_.now_fn() : system_now_secs();

    // ── Pass 1: matcher ────────────────────────────────────────────────────
    // Registry info per norm_key (the id for alias writes; the stored
    // vendor/title for posture rows and alert copy).
    struct KeyInfo {
        std::int64_t product_id{0};
        std::string vendor;
        std::string title;
    };
    std::unordered_map<std::string, KeyInfo> by_key;
    std::vector<ProductCandidate> candidates;

    std::optional<std::vector<ProductRow>> products;
    if (d_.list_products)
        products = d_.list_products();
    if (!products) {
        spdlog::warn("SLE evaluator: registry candidate read degraded — skipping cycle "
                     "(keep-last-good)");
        return TickOutcome::degraded;
    }
    candidates.reserve(products->size());
    for (const auto& p : *products) {
        candidates.push_back(ProductCandidate{p.norm_key, p.title, p.vendor});
        by_key.emplace(p.norm_key, KeyInfo{p.product_id, p.vendor, p.title});
    }

    std::optional<std::vector<DetectedProduct>> detected;
    if (d_.distinct_products)
        detected = d_.distinct_products();
    if (!detected) {
        spdlog::warn("SLE evaluator: detected-product read degraded — skipping cycle");
        return TickOutcome::degraded;
    }
    // Raw detected pair -> norm_key ('' = the honest unmatched bucket). The
    // rollup pass joins through THIS map, never a resolve_alias read-back —
    // the matcher just computed every link, and a read-back would add one
    // degrade point per row and could observe another instance's mid-cycle
    // writes.
    std::unordered_map<std::string, std::string> detected_key;
    detected_key.reserve(detected->size());
    for (const auto& p : *detected) {
        const MatchResult m = match_product(p.product, p.vendor, candidates);
        std::string key;
        std::int64_t product_id = 0;
        if (m.tier == MatchTier::birth) {
            const NormalizedTitle nt = normalize_title(p.product);
            if (nt.title.empty()) {
                // Unmatchable (a raw title that normalises away, e.g. "2019")
                // — file it under the unmatched bucket, no registry write.
                detected_key.emplace(pair_key(p.product, p.vendor), std::string{});
                continue;
            }
            key = norm_key(p.product, p.vendor);
            const std::string vendor_n = normalize_vendor(p.vendor);
            auto id = d_.upsert_product(key, vendor_n, nt.title, nt.edition, "");
            if (!id) {
                // F4: a failed birth would misfile this product into '' —
                // a WRONG rollup, and a mid-cycle write failure almost
                // certainly means PG trouble. Abort before the replace.
                spdlog::warn("SLE evaluator: product birth failed for '{}' — skipping cycle",
                             key);
                return TickOutcome::degraded;
            }
            by_key.emplace(key, KeyInfo{*id, vendor_n, nt.title});
            // Later pairs in this same cycle tier-match the new candidate
            // deterministically instead of re-birthing it.
            candidates.push_back(ProductCandidate{key, nt.title, vendor_n});
            product_id = *id;
        } else {
            key = m.norm_key;
            product_id = by_key[key].product_id;
        }
        // Alias refresh EVERY cycle (R7): last_seen_at is the "this link is
        // still being derived" signal. Fail-soft — the in-memory key still
        // drives this cycle's join; the link re-derives next cycle.
        if (!d_.upsert_alias("software_licensing", p.product, p.vendor, product_id,
                             tier_name(m.tier), m.confidence))
            spdlog::warn("SLE evaluator: alias upsert failed for detected ('{}', '{}')",
                         p.product, p.vendor);
        detected_key.emplace(pair_key(p.product, p.vendor), std::move(key));
    }

    std::optional<std::vector<SoftwareCatalogRow>> catalog;
    if (d_.software_catalog)
        catalog = d_.software_catalog();
    if (!catalog) {
        // install_count would silently read as zero fleet-wide — a false
        // "installed-but-unreported" collapse. Abort (F4).
        spdlog::warn("SLE evaluator: installed-software catalogue read degraded — skipping "
                     "cycle");
        return TickOutcome::degraded;
    }
    std::unordered_map<std::string, std::int64_t> install_counts;
    for (const auto& c : *catalog) {
        const MatchResult m = match_product(c.name, c.publisher, candidates);
        // Installed-software titles NEVER birth registry rows: the registry
        // is the identity plane for products the licence detector sees;
        // birthing here would flood it with every unlicensed title.
        if (m.tier == MatchTier::birth)
            continue;
        if (!d_.upsert_alias("installed_software", c.name, c.publisher,
                             by_key[m.norm_key].product_id, tier_name(m.tier), m.confidence))
            spdlog::warn("SLE evaluator: alias upsert failed for catalogue ('{}', '{}')",
                         c.name, c.publisher);
        install_counts[m.norm_key] += c.device_count;
    }

    // ── Pass 2: posture rollup ─────────────────────────────────────────────
    std::optional<LicensePostureInputs> inputs;
    if (d_.posture_inputs)
        inputs = d_.posture_inputs();
    if (!inputs) {
        spdlog::warn("SLE evaluator: posture-input read degraded — skipping cycle");
        return TickOutcome::degraded;
    }
    // A pair ingested between the distinct_products and posture_inputs reads
    // is matched on the fly (pure, no writes): a would-be birth files under
    // '' for this cycle and births next cycle.
    const auto key_for = [&](const std::string& product,
                             const std::string& vendor) -> std::string {
        const auto it = detected_key.find(pair_key(product, vendor));
        if (it != detected_key.end())
            return it->second;
        const MatchResult m = match_product(product, vendor, candidates);
        return m.tier == MatchTier::birth ? std::string{} : m.norm_key;
    };
    // std::map: deterministic row order for tests and stable alert-pass
    // iteration ('' sorts first and is skipped by the alert pass).
    std::map<std::string, LicensePostureRow> agg;
    for (const auto& g : inputs->groups) {
        const std::string key = key_for(g.product, g.vendor);
        LicensePostureRow& r = agg[key];
        r.product_key = key;
        const std::string eff =
            effective_license_state(g.state, g.license_type, g.expiry_at, now);
        if (eff == "licensed")
            r.licensed_count += g.row_count;
        else if (eff == "subscription_active")
            r.subscription_active_count += g.row_count;
        else if (eff == "trial")
            r.trial_count += g.row_count;
        else if (eff == "grace")
            r.grace_count += g.row_count;
        else if (eff == "expired")
            r.expired_count += g.row_count;
        else if (eff == "unlicensed")
            r.unlicensed_count += g.row_count;
        else
            r.unknown_count += g.row_count;
        if (g.expiry_at > now && (r.next_expiry_at == 0 || g.expiry_at < r.next_expiry_at))
            r.next_expiry_at = g.expiry_at;
        const bool active = eff == "licensed" || eff == "subscription_active" ||
                            eff == "trial" || eff == "grace";
        if (active && g.expiry_at > now &&
            g.expiry_at <= now + std::int64_t{kExpiryWarnDays} * 86400)
            r.expiring_soon_count += g.row_count;
    }
    for (const auto& p : inputs->pair_device_counts) {
        const std::string key = key_for(p.product, p.vendor);
        LicensePostureRow& r = agg[key];
        r.product_key = key;
        // Σ per-pair distinct counts over the key's pairs — a documented
        // upper bound (see LicensePairDeviceCount).
        r.device_count += p.device_count;
    }
    std::vector<LicensePostureRow> rows;
    rows.reserve(agg.size());
    for (auto& [key, r] : agg) {
        if (!key.empty()) {
            const auto it = by_key.find(key);
            if (it != by_key.end()) {
                r.vendor = it->second.vendor;
                r.title = it->second.title;
            }
            const auto ic = install_counts.find(key);
            r.install_count = ic != install_counts.end() ? ic->second : 0;
        }
        // The '' bucket keeps empty vendor/title (the page renders it as
        // "(unmatched)") and never joins install_count.
        r.refreshed_at = now;
        rows.push_back(std::move(r));
    }

    if (!d_.replace_posture_rollup(rows, now)) {
        // Keep-last-good is the store's txn rollback; alerting on rows the
        // surface never got would desynchronise alerts from the page.
        spdlog::warn("SLE evaluator: posture-rollup replace failed — alert pass skipped");
        return TickOutcome::error;
    }

    // ── Pass 3: alerts ─────────────────────────────────────────────────────
    const auto process = [&](const LicensePostureRow& r, const char* kind, std::int64_t bucket,
                             std::string fingerprint, std::int64_t days_left) {
        auto prior = d_.alert_state(r.product_key, kind);
        if (!prior) {
            // A degrade must never read as "never fired" (it would re-fire
            // every degraded cycle).
            if (d_.metrics)
                d_.metrics
                    ->counter("yuzu_server_sle_alert_suppressed_total",
                              {{"kind", kind}, {"reason", "state_degraded"}})
                    .increment();
            return;
        }
        const SleAlertDecision dec = sle_decide_alert(*prior, bucket, now);
        if (!dec.fire) {
            if (d_.metrics)
                d_.metrics
                    ->counter("yuzu_server_sle_alert_suppressed_total",
                              {{"kind", kind}, {"reason", "holddown"}})
                    .increment();
            return;
        }
        // Arm BEFORE delivering (the dex "cooldown already armed" posture).
        // A failed arm still emits: the worst case is one bounded duplicate
        // next cycle (exactly the G-3 dedup-state-loss burst) — losing the
        // alert would be the worse failure.
        if (!d_.upsert_alert_state(r.product_key, kind, fingerprint, bucket, now))
            spdlog::warn("SLE evaluator: alert-state arm failed for ({}, {}) — emitting anyway",
                         r.product_key, kind);
        if (d_.metrics)
            d_.metrics->counter("yuzu_server_sle_alert_fired_total", {{"kind", kind}})
                .increment();
        SleAlert a;
        a.kind = kind;
        a.product_key = r.product_key;
        a.vendor = r.vendor;
        a.title = r.title;
        a.device_count = r.device_count;
        a.next_expiry_at = r.next_expiry_at;
        a.days_left = days_left;
        a.bucket = bucket;
        if (d_.on_alert) {
            try {
                d_.on_alert(a);
            } catch (const std::exception& e) {
                spdlog::warn("SLE evaluator: alert sink threw for ({}, {}): {}", r.product_key,
                             kind, e.what());
                if (d_.metrics)
                    d_.metrics->counter("yuzu_server_sle_alert_delivery_failed_total")
                        .increment();
            } catch (...) {
                spdlog::warn("SLE evaluator: alert sink threw for ({}, {})", r.product_key,
                             kind);
                if (d_.metrics)
                    d_.metrics->counter("yuzu_server_sle_alert_delivery_failed_total")
                        .increment();
            }
        }
    };

    for (const auto& r : rows) {
        if (r.product_key.empty())
            continue; // an identity-less notification is noise; the page
                      // surfaces the '' bucket instead
        if (const auto bucket = sle_expiring_bucket(r.next_expiry_at, now))
            process(r, "expiring", *bucket, std::to_string(r.next_expiry_at),
                    ceil_days(r.next_expiry_at, now));
        // R11: expired_count ALONE drives "expired" — unlicensed /
        // over-deployment deliberately never alert in v1.
        if (r.expired_count > 0)
            process(r, "expired", 0, "expired", 0);
    }
    return TickOutcome::success;
}

void LicenseComplianceEvaluator::run() {
    spdlog::info("SLE compliance evaluator thread started (interval={}s)", d_.interval.count());
    // Seed the liveness gauge to 0 BEFORE the first tick (gov UP-2): seeded,
    // the series always exists and the staleness alert's `> 0` guard skips
    // the building window; unseeded, a server whose first cycles keep
    // failing has no gauge for the alert to evaluate.
    if (d_.metrics)
        d_.metrics->gauge("yuzu_server_sle_evaluator_last_success_timestamp").set(0);
    bool first = true;
    while (!stop_.load(std::memory_order_acquire)) {
        if (!first) {
            // Completion-spaced cadence in 5s steps (shutdown-responsive):
            // spacing measured from the END of the previous cycle, so a slow
            // cycle backs off instead of overlapping the next.
            const std::int64_t steps = (d_.interval.count() + 4) / 5;
            for (std::int64_t i = 0; i < steps && !stop_.load(std::memory_order_acquire); ++i)
                std::this_thread::sleep_for(std::chrono::seconds{5});
            if (stop_.load(std::memory_order_acquire))
                break;
        }
        first = false;
        // tick() touches PG through the providers; an exception escaping a
        // std::thread entry calls std::terminate — catch, count, keep going.
        try {
            const auto t0 = std::chrono::steady_clock::now();
            const TickOutcome outcome = tick();
            const double secs =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            if (d_.metrics) {
                const char* label = outcome == TickOutcome::success   ? "success"
                                    : outcome == TickOutcome::degraded ? "degraded"
                                                                        : "error";
                d_.metrics
                    ->counter("yuzu_server_sle_evaluator_runs_total", {{"outcome", label}})
                    .increment();
                d_.metrics->gauge("yuzu_server_sle_evaluator_duration_seconds").set(secs);
                if (outcome == TickOutcome::success)
                    d_.metrics->gauge("yuzu_server_sle_evaluator_last_success_timestamp")
                        .set(static_cast<double>(d_.now_fn ? d_.now_fn() : system_now_secs()));
            }
        } catch (const std::exception& e) {
            spdlog::error("SLE evaluator: tick threw ({}) — thread continuing", e.what());
            if (d_.metrics)
                d_.metrics
                    ->counter("yuzu_server_sle_evaluator_runs_total", {{"outcome", "error"}})
                    .increment();
        } catch (...) {
            spdlog::error("SLE evaluator: tick threw unknown exception — thread continuing");
            if (d_.metrics)
                d_.metrics
                    ->counter("yuzu_server_sle_evaluator_runs_total", {{"outcome", "error"}})
                    .increment();
        }
    }
}

} // namespace yuzu::server
