// LicenseComplianceEvaluator tests (ADR-0024 Decisions 6/7/8): the pure alert
// decision machinery (buckets, worsening-only escalation, 7-day re-arm,
// hold-down, the G-3 first-evaluation burst), the three-pass tick over fake
// injected Deps (matcher births/aliases, posture derivation, the F4
// skip-cycle rule on every authoritative-input degrade), and the thread
// lifecycle. Everything except the final smoke runs WITHOUT Postgres — the
// payoff of the injected-Deps design.

#include <catch2/catch_test_macros.hpp>

#include "license_compliance_evaluator.hpp"
#include "pg/pg_pool.hpp"
#include "product_normalize.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::DetectedProduct;
using yuzu::server::kRearmSecs;
using yuzu::server::LicenseAlertState;
using yuzu::server::LicenseComplianceEvaluator;
using yuzu::server::LicensePairDeviceCount;
using yuzu::server::LicensePostureInputGroup;
using yuzu::server::LicensePostureInputs;
using yuzu::server::LicensePostureRow;
using yuzu::server::LicensingReadError;
using yuzu::server::ProductRow;
using yuzu::server::sle_alert_event_type;
using yuzu::server::sle_alert_payload;
using yuzu::server::sle_decide_alert;
using yuzu::server::sle_expiring_bucket;
using yuzu::server::SleAlert;
using yuzu::server::SleAlertDecision;
using yuzu::server::SoftwareCatalogRow;
using TickOutcome = yuzu::server::LicenseComplianceEvaluator::TickOutcome;

namespace {

constexpr std::int64_t kDay = 86400;
constexpr std::int64_t kNow0 = 1'800'000'000; // fixed test epoch

/// Fake-Deps harness: every provider serves in-memory fixtures, every write
/// is recorded, and the clock is a settable field. Degrade flags flip any
/// authoritative read to nullopt/kDegraded.
struct EvalHarness {
    std::int64_t now{kNow0};

    std::vector<ProductRow> products;
    std::vector<DetectedProduct> detected;
    LicensePostureInputs inputs;
    std::vector<SoftwareCatalogRow> catalog;

    bool degrade_products{false};
    bool degrade_detected{false};
    bool degrade_inputs{false};
    bool degrade_catalog{false};
    bool degrade_alert_state{false};
    bool fail_upsert_product{false};
    bool fail_upsert_alias{false};
    bool fail_replace{false};
    bool fail_upsert_alert_state{false};
    bool sink_throws{false};

    // Recorders.
    struct UpsertedProduct {
        std::string norm_key, vendor, title, edition;
    };
    struct UpsertedAlias {
        std::string source, raw_name, raw_publisher, method;
        std::int64_t product_id;
        double confidence;
    };
    std::vector<UpsertedProduct> upserted_products;
    std::vector<UpsertedAlias> upserted_aliases;
    std::vector<std::vector<LicensePostureRow>> replaced;
    std::vector<SleAlert> emitted;
    std::map<std::string, LicenseAlertState> alert_states; // key \x1f kind
    std::int64_t next_product_id{100};

    yuzu::MetricsRegistry metrics;

    static std::string sk(std::string_view key, std::string_view kind) {
        return std::string(key) + '\x1f' + std::string(kind);
    }

    LicenseComplianceEvaluator::Deps deps() {
        LicenseComplianceEvaluator::Deps d;
        d.list_products = [this]() -> std::optional<std::vector<ProductRow>> {
            if (degrade_products)
                return std::nullopt;
            return products;
        };
        d.distinct_products = [this]() -> std::optional<std::vector<DetectedProduct>> {
            if (degrade_detected)
                return std::nullopt;
            return detected;
        };
        d.posture_inputs = [this]() -> std::optional<LicensePostureInputs> {
            if (degrade_inputs)
                return std::nullopt;
            return inputs;
        };
        d.software_catalog = [this]() -> std::optional<std::vector<SoftwareCatalogRow>> {
            if (degrade_catalog)
                return std::nullopt;
            return catalog;
        };
        d.upsert_product = [this](std::string_view nk, std::string_view v, std::string_view t,
                                  std::string_view e,
                                  std::string_view) -> std::optional<std::int64_t> {
            if (fail_upsert_product)
                return std::nullopt;
            upserted_products.push_back(
                {std::string(nk), std::string(v), std::string(t), std::string(e)});
            // Mirror the store: a new norm_key mints an id; re-upsert reuses.
            for (const auto& p : products)
                if (p.norm_key == nk)
                    return p.product_id;
            ProductRow row;
            row.product_id = next_product_id++;
            row.norm_key = std::string(nk);
            row.vendor = std::string(v);
            row.title = std::string(t);
            products.push_back(row);
            return row.product_id;
        };
        d.upsert_alias = [this](std::string_view src, std::string_view rn, std::string_view rp,
                                std::int64_t pid, std::string_view method, double conf) -> bool {
            if (fail_upsert_alias)
                return false;
            upserted_aliases.push_back({std::string(src), std::string(rn), std::string(rp),
                                        std::string(method), pid, conf});
            return true;
        };
        d.replace_posture_rollup = [this](const std::vector<LicensePostureRow>& rows,
                                          std::int64_t) -> bool {
            if (fail_replace)
                return false;
            replaced.push_back(rows);
            return true;
        };
        d.alert_state =
            [this](std::string_view key, std::string_view kind)
            -> std::expected<std::optional<LicenseAlertState>, LicensingReadError> {
            if (degrade_alert_state)
                return std::unexpected(LicensingReadError::kDegraded);
            const auto it = alert_states.find(sk(key, kind));
            if (it == alert_states.end())
                return std::optional<LicenseAlertState>{};
            return std::optional<LicenseAlertState>{it->second};
        };
        d.upsert_alert_state = [this](std::string_view key, std::string_view kind,
                                      std::string_view fp, std::int64_t bucket,
                                      std::int64_t fired_at) -> bool {
            if (fail_upsert_alert_state)
                return false;
            alert_states[sk(key, kind)] =
                LicenseAlertState{std::string(fp), bucket, fired_at};
            return true;
        };
        d.on_alert = [this](const SleAlert& a) {
            if (sink_throws)
                throw std::runtime_error("sink boom");
            emitted.push_back(a);
        };
        d.now_fn = [this] { return now; };
        d.metrics = &metrics;
        return d;
    }

    TickOutcome tick() {
        LicenseComplianceEvaluator ev{deps()};
        return ev.tick();
    }

    double fired(const char* kind) {
        return metrics.counter("yuzu_server_sle_alert_fired_total", {{"kind", kind}}).value();
    }
    double suppressed(const char* kind, const char* reason) {
        return metrics
            .counter("yuzu_server_sle_alert_suppressed_total",
                     {{"kind", kind}, {"reason", reason}})
            .value();
    }
    const std::vector<LicensePostureRow>& last_rollup() {
        REQUIRE_FALSE(replaced.empty());
        return replaced.back();
    }
};

ProductRow product(std::int64_t id, const std::string& nk, const std::string& vendor,
                   const std::string& title) {
    ProductRow p;
    p.product_id = id;
    p.norm_key = nk;
    p.vendor = vendor;
    p.title = title;
    return p;
}

LicensePostureInputGroup group(const std::string& product, const std::string& state,
                               std::int64_t expiry_at, std::int64_t rows, std::int64_t devices,
                               const std::string& vendor = "Acme Inc",
                               const std::string& license_type = "perpetual") {
    LicensePostureInputGroup g;
    g.product = product;
    g.vendor = vendor;
    g.state = state;
    g.license_type = license_type;
    g.expiry_at = expiry_at;
    g.row_count = rows;
    g.device_count = devices;
    return g;
}

LicensePairDeviceCount pair_count(const std::string& product, std::int64_t devices,
                                  const std::string& vendor = "Acme Inc") {
    LicensePairDeviceCount p;
    p.product = product;
    p.vendor = vendor;
    p.device_count = devices;
    return p;
}

/// The standard one-product fixture: "Reader" by "Acme Inc" matches the
/// registry row acme:reader (exact_norm once normalised).
void seed_reader(EvalHarness& h, const std::string& state, std::int64_t expiry_at,
                 std::int64_t rows = 1, std::int64_t devices = 1) {
    h.products = {product(1, "acme:reader", "acme", "reader")};
    h.detected = {DetectedProduct{"Reader", "Acme Inc"}};
    h.inputs.groups = {group("Reader", state, expiry_at, rows, devices)};
    h.inputs.pair_device_counts = {pair_count("Reader", devices)};
}

} // namespace

// ── Pure decision functions ──────────────────────────────────────────────────

TEST_CASE("sle_expiring_bucket derives 30/14/7/1 from ceiling days-to-expiry",
          "[sle][evaluator]") {
    const std::int64_t now = kNow0;
    CHECK_FALSE(sle_expiring_bucket(now + 31 * kDay, now).has_value());
    CHECK(sle_expiring_bucket(now + 30 * kDay, now) == 30);
    CHECK(sle_expiring_bucket(now + 15 * kDay, now) == 30);
    CHECK(sle_expiring_bucket(now + 14 * kDay, now) == 14);
    CHECK(sle_expiring_bucket(now + 8 * kDay, now) == 14);
    CHECK(sle_expiring_bucket(now + 7 * kDay, now) == 7);
    CHECK(sle_expiring_bucket(now + 2 * kDay, now) == 7);
    CHECK(sle_expiring_bucket(now + 1 * kDay, now) == 1);
    CHECK(sle_expiring_bucket(now + 3600, now) == 1); // partial day ceils to 1
    CHECK_FALSE(sle_expiring_bucket(now, now).has_value());          // expired's territory
    CHECK_FALSE(sle_expiring_bucket(now - kDay, now).has_value());   // past
    CHECK_FALSE(sle_expiring_bucket(0, now).has_value());            // no expiry
}

TEST_CASE("sle_decide_alert: first-eval, worsening-only, re-arm, hold-down",
          "[sle][evaluator]") {
    using Reason = SleAlertDecision::Reason;
    const std::int64_t now = kNow0;

    SECTION("no prior row fires first_eval (G-3)") {
        const auto d = sle_decide_alert(std::nullopt, 30, now);
        CHECK(d.fire);
        CHECK(d.reason == Reason::first_eval);
    }
    SECTION("worse bucket fires; same or better holds down") {
        const LicenseAlertState prior{"fp", 14, now - 3600};
        CHECK(sle_decide_alert(prior, 7, now).fire);
        CHECK(sle_decide_alert(prior, 7, now).reason == Reason::worsened);
        CHECK_FALSE(sle_decide_alert(prior, 14, now).fire);
        CHECK_FALSE(sle_decide_alert(prior, 30, now).fire); // improving never fires
        CHECK(sle_decide_alert(prior, 30, now).reason == Reason::holddown);
    }
    SECTION("persistence past the 7-day re-arm fires; 6d23h does not") {
        const LicenseAlertState armed{"fp", 14, now - kRearmSecs};
        CHECK(sle_decide_alert(armed, 14, now).fire);
        CHECK(sle_decide_alert(armed, 14, now).reason == Reason::rearmed);
        const LicenseAlertState fresh{"fp", 14, now - kRearmSecs + 3600};
        CHECK_FALSE(sle_decide_alert(fresh, 14, now).fire);
    }
}

TEST_CASE("§3.4 payload contract: event types and exactly the eight keys",
          "[sle][evaluator]") {
    CHECK(sle_alert_event_type("expiring") == "software_license.expiring");
    CHECK(sle_alert_event_type("expired") == "software_license.expired");

    SleAlert a;
    a.kind = "expiring";
    a.product_key = "acme:reader";
    a.vendor = "acme";
    a.title = "reader";
    a.device_count = 4;
    a.next_expiry_at = kNow0 + 10 * kDay;
    a.days_left = 10;
    a.bucket = 14;
    const auto j = sle_alert_payload(a);
    REQUIRE(j.size() == 8);
    CHECK(j.at("event") == "software_license.expiring");
    CHECK(j.at("product_key") == "acme:reader");
    CHECK(j.at("vendor") == "acme");
    CHECK(j.at("title") == "reader");
    CHECK(j.at("device_count") == 4);
    CHECK(j.at("next_expiry_at") == kNow0 + 10 * kDay);
    CHECK(j.at("days_left") == 10);
    CHECK(j.at("bucket") == 14);
}

// ── The tick over fake Deps: alert semantics ────────────────────────────────

TEST_CASE("first evaluation fires once per product then holds down (G-3)",
          "[sle][evaluator]") {
    EvalHarness h;
    h.products = {product(1, "acme:reader", "acme", "reader"),
                  product(2, "acme:writer", "acme", "writer")};
    h.detected = {DetectedProduct{"Reader", "Acme Inc"}, DetectedProduct{"Writer", "Acme Inc"}};
    h.inputs.groups = {group("Reader", "subscription_active", kNow0 + 10 * kDay, 1, 1),
                       group("Writer", "subscription_active", kNow0 + 10 * kDay, 1, 1)};
    h.inputs.pair_device_counts = {pair_count("Reader", 1), pair_count("Writer", 1)};

    REQUIRE(h.tick() == TickOutcome::success);
    // Bounded burst: exactly one fire per product in-condition.
    CHECK(h.emitted.size() == 2);
    CHECK(h.fired("expiring") == 2.0);

    // Immediate second tick: both held down.
    REQUIRE(h.tick() == TickOutcome::success);
    CHECK(h.emitted.size() == 2);
    CHECK(h.suppressed("expiring", "holddown") == 2.0);

    // Dedup-state loss re-fires once (the bounded G-3 burst, not spam).
    h.alert_states.clear();
    REQUIRE(h.tick() == TickOutcome::success);
    CHECK(h.emitted.size() == 4);
}

TEST_CASE("worsening bucket transition fires; same bucket holds down", "[sle][evaluator]") {
    EvalHarness h;
    seed_reader(h, "subscription_active", kNow0 + 20 * kDay);
    REQUIRE(h.tick() == TickOutcome::success); // first_eval at bucket 30
    REQUIRE(h.emitted.size() == 1);
    CHECK(h.emitted[0].bucket == 30);

    h.now = kNow0 + 10 * kDay; // 10 days left -> bucket 14 (worse than 30)
    REQUIRE(h.tick() == TickOutcome::success);
    REQUIRE(h.emitted.size() == 2);
    CHECK(h.emitted[1].bucket == 14);
    CHECK(h.emitted[1].days_left == 10);

    REQUIRE(h.tick() == TickOutcome::success); // same bucket -> holddown
    CHECK(h.emitted.size() == 2);
}

TEST_CASE("improving never fires and never clobbers the recorded bucket",
          "[sle][evaluator]") {
    EvalHarness h;
    seed_reader(h, "subscription_active", kNow0 + 5 * kDay);
    REQUIRE(h.tick() == TickOutcome::success); // first_eval at bucket 7
    REQUIRE(h.emitted.size() == 1);
    CHECK(h.emitted[0].bucket == 7);

    // Renewal: expiry shifts LATER (bucket 30, new fingerprint) inside the
    // hold-down window — suppressed, and the prior bucket survives.
    h.inputs.groups = {group("Reader", "subscription_active", kNow0 + 25 * kDay, 1, 1)};
    REQUIRE(h.tick() == TickOutcome::success);
    CHECK(h.emitted.size() == 1);
    CHECK(h.suppressed("expiring", "holddown") == 1.0);
    CHECK(h.alert_states.at(EvalHarness::sk("acme:reader", "expiring")).bucket == 7);
}

TEST_CASE("expired: clear-then-re-assert inside the re-arm window is suppressed; "
          "persistence past it re-fires",
          "[sle][evaluator]") {
    EvalHarness h;
    seed_reader(h, "expired", 0);
    REQUIRE(h.tick() == TickOutcome::success); // first_eval
    REQUIRE(h.emitted.size() == 1);
    CHECK(h.emitted[0].kind == "expired");
    CHECK(h.emitted[0].bucket == 0);
    CHECK(h.emitted[0].days_left == 0);

    // Clears (renewed): no condition, nothing fires, state row persists.
    h.inputs.groups = {group("Reader", "licensed", 0, 1, 1)};
    REQUIRE(h.tick() == TickOutcome::success);
    CHECK(h.emitted.size() == 1);

    // Re-asserts one hour later: prior row (bucket 0) holds it down.
    h.now = kNow0 + 3600;
    h.inputs.groups = {group("Reader", "expired", 0, 1, 1)};
    REQUIRE(h.tick() == TickOutcome::success);
    CHECK(h.emitted.size() == 1);
    CHECK(h.suppressed("expired", "holddown") == 1.0);

    // Persistence past the re-arm window re-fires.
    h.now = kNow0 + kRearmSecs;
    REQUIRE(h.tick() == TickOutcome::success);
    CHECK(h.emitted.size() == 2);
}

TEST_CASE("expired fires on expired_count > 0 only; unlicensed alone never alerts (R11)",
          "[sle][evaluator]") {
    EvalHarness h;
    seed_reader(h, "unlicensed", 0);
    REQUIRE(h.tick() == TickOutcome::success);
    CHECK(h.emitted.empty());
    CHECK(h.fired("expired") == 0.0);
    // The posture row still carries the honest count.
    REQUIRE(h.last_rollup().size() == 1);
    CHECK(h.last_rollup()[0].unlicensed_count == 1);
}

TEST_CASE("expired and expiring dedup independently per (product_key, kind)",
          "[sle][evaluator]") {
    EvalHarness h;
    h.products = {product(1, "acme:reader", "acme", "reader")};
    h.detected = {DetectedProduct{"Reader", "Acme Inc"}};
    // One expired row + one active row expiring in 5 days: both conditions.
    h.inputs.groups = {group("Reader", "expired", 0, 1, 1),
                       group("Reader", "subscription_active", kNow0 + 5 * kDay, 1, 1)};
    h.inputs.pair_device_counts = {pair_count("Reader", 2)};

    REQUIRE(h.tick() == TickOutcome::success);
    REQUIRE(h.emitted.size() == 2);
    CHECK(h.fired("expiring") == 1.0);
    CHECK(h.fired("expired") == 1.0);
    // Independent state rows.
    CHECK(h.alert_states.count(EvalHarness::sk("acme:reader", "expiring")) == 1);
    CHECK(h.alert_states.count(EvalHarness::sk("acme:reader", "expired")) == 1);
    // Both hold down independently on the next tick.
    REQUIRE(h.tick() == TickOutcome::success);
    CHECK(h.emitted.size() == 2);
}

TEST_CASE("a degraded alert-state read suppresses — never re-fires, never resets dedup",
          "[sle][evaluator]") {
    EvalHarness h;
    seed_reader(h, "expired", 0);
    // Prior state exists (fired long ago — would re-arm if readable).
    h.alert_states[EvalHarness::sk("acme:reader", "expired")] =
        LicenseAlertState{"expired", 0, kNow0 - 2 * kRearmSecs};

    h.degrade_alert_state = true;
    REQUIRE(h.tick() == TickOutcome::success); // the CYCLE still succeeds
    CHECK(h.emitted.empty());
    CHECK(h.suppressed("expired", "state_degraded") == 1.0);
    // The dedup row survived untouched.
    CHECK(h.alert_states.at(EvalHarness::sk("acme:reader", "expired")).last_fired_at ==
          kNow0 - 2 * kRearmSecs);

    // Healthy next tick: prior is readable again — re-arm applies normally.
    h.degrade_alert_state = false;
    REQUIRE(h.tick() == TickOutcome::success);
    CHECK(h.emitted.size() == 1);
}

// ── The F4 rule: degrade is not a false all-clear ───────────────────────────

TEST_CASE("each authoritative input degrade skips the cycle before the replace (F4)",
          "[sle][evaluator]") {
    EvalHarness h;
    seed_reader(h, "expired", 0);

    SECTION("registry candidates degrade") { h.degrade_products = true; }
    SECTION("detected products degrade") { h.degrade_detected = true; }
    SECTION("posture inputs degrade") { h.degrade_inputs = true; }
    SECTION("installed-software catalogue degrades") { h.degrade_catalog = true; }

    CHECK(h.tick() == TickOutcome::degraded);
    CHECK(h.replaced.empty()); // keep-last-good: the replace never ran
    CHECK(h.emitted.empty());  // and nothing alerted off partial inputs
}

TEST_CASE("a failed birth aborts the cycle; a failed alias upsert is tolerated",
          "[sle][evaluator]") {
    EvalHarness h;
    // Empty registry: the detected product must birth.
    h.detected = {DetectedProduct{"NewApp", "NewVendor"}};
    h.inputs.groups = {group("NewApp", "licensed", 0, 1, 1, "NewVendor")};
    h.inputs.pair_device_counts = {pair_count("NewApp", 1, "NewVendor")};

    SECTION("birth write failure -> degraded, no replace") {
        h.fail_upsert_product = true;
        CHECK(h.tick() == TickOutcome::degraded);
        CHECK(h.replaced.empty());
    }
    SECTION("alias write failure -> warn + continue; the cycle succeeds") {
        h.fail_upsert_alias = true;
        CHECK(h.tick() == TickOutcome::success);
        REQUIRE(h.replaced.size() == 1);
        // The in-memory key still drove the join — the row is NOT in ''.
        REQUIRE(h.last_rollup().size() == 1);
        CHECK(h.last_rollup()[0].product_key == "newvendor:newapp");
    }
}

TEST_CASE("a failed rollup replace skips the alert pass (outcome error)",
          "[sle][evaluator]") {
    EvalHarness h;
    seed_reader(h, "expired", 0);
    h.fail_replace = true;
    CHECK(h.tick() == TickOutcome::error);
    CHECK(h.emitted.empty());
    CHECK(h.fired("expired") == 0.0);
}

// ── Matcher + rollup derivation ─────────────────────────────────────────────

TEST_CASE("matcher births detected products and refreshes aliases every cycle (R7)",
          "[sle][evaluator]") {
    EvalHarness h;
    h.detected = {DetectedProduct{"NewApp", "NewVendor"}};
    h.inputs.groups = {group("NewApp", "licensed", 0, 1, 1, "NewVendor")};
    h.inputs.pair_device_counts = {pair_count("NewApp", 1, "NewVendor")};

    REQUIRE(h.tick() == TickOutcome::success);
    REQUIRE(h.upserted_products.size() == 1);
    CHECK(h.upserted_products[0].norm_key == "newvendor:newapp");
    REQUIRE(h.upserted_aliases.size() == 1);
    CHECK(h.upserted_aliases[0].source == "software_licensing");
    CHECK(h.upserted_aliases[0].method == "birth");
    CHECK(h.upserted_aliases[0].confidence == 0.0);

    // Second tick: the birthed row is now a registry candidate — the same
    // pair tier-matches (exact_norm) and the alias refreshes AGAIN (R7).
    REQUIRE(h.tick() == TickOutcome::success);
    REQUIRE(h.upserted_aliases.size() == 2);
    CHECK(h.upserted_aliases[1].method == "exact_norm");
    CHECK(h.upserted_aliases[1].confidence == 1.0);
    // No re-birth of an existing candidate.
    CHECK(h.upserted_products.size() == 1);
}

TEST_CASE("installed-software catalogue rows join install_count but never birth",
          "[sle][evaluator]") {
    EvalHarness h;
    seed_reader(h, "licensed", 0, 2, 2);
    SoftwareCatalogRow matched;
    matched.name = "Reader";
    matched.publisher = "Acme Inc";
    matched.device_count = 7;
    SoftwareCatalogRow unmatched;
    unmatched.name = "7-zip";
    unmatched.publisher = "Igor Pavlov";
    unmatched.device_count = 900;
    h.catalog = {matched, unmatched};

    REQUIRE(h.tick() == TickOutcome::success);
    // The matched title contributed install_count; the unmatched one neither
    // birthed nor aliased.
    REQUIRE(h.last_rollup().size() == 1);
    CHECK(h.last_rollup()[0].install_count == 7);
    CHECK(h.upserted_products.empty());
    bool has_installed_alias = false;
    for (const auto& a : h.upserted_aliases)
        if (a.source == "installed_software") {
            has_installed_alias = true;
            CHECK(a.raw_name == "Reader");
        }
    CHECK(has_installed_alias);
}

TEST_CASE("unmatched detected rows aggregate into the '' bucket and never alert",
          "[sle][evaluator]") {
    EvalHarness h;
    // "2019" normalises away entirely -> unmatchable -> the '' bucket, even
    // though its rows are expired.
    h.detected = {DetectedProduct{"2019", "NoVendor"}};
    h.inputs.groups = {group("2019", "expired", 0, 3, 2, "NoVendor")};
    h.inputs.pair_device_counts = {pair_count("2019", 2, "NoVendor")};

    REQUIRE(h.tick() == TickOutcome::success);
    CHECK(h.upserted_products.empty()); // no registry write for the unmatchable
    REQUIRE(h.last_rollup().size() == 1);
    const auto& r = h.last_rollup()[0];
    CHECK(r.product_key == "");
    CHECK(r.expired_count == 3);
    CHECK(r.device_count == 2);
    CHECK(h.emitted.empty()); // the '' bucket never alerts
    CHECK(h.fired("expired") == 0.0);
}

TEST_CASE("posture rows carry the cycle as-of and honest per-state counts",
          "[sle][evaluator]") {
    EvalHarness h;
    h.products = {product(1, "acme:reader", "acme", "reader")};
    h.detected = {DetectedProduct{"Reader", "Acme Inc"}};
    // Groups exercising the Decision 7 lapse rule and the expiring window:
    //  - licensed, no expiry: stays licensed.
    //  - subscription_active expiring in 10d: active + expiring-soon.
    //  - subscription_active expired 1d ago: lapses to expired.
    //  - trial expiring in 40d: active, outside the 30d window.
    //  - garbage state: whitelists to unknown.
    h.inputs.groups = {
        group("Reader", "licensed", 0, 2, 2),
        group("Reader", "subscription_active", kNow0 + 10 * kDay, 3, 3),
        group("Reader", "subscription_active", kNow0 - kDay, 1, 1),
        group("Reader", "trial", kNow0 + 40 * kDay, 1, 1),
        group("Reader", "bogus_state", 0, 1, 1),
    };
    h.inputs.pair_device_counts = {pair_count("Reader", 4)};

    REQUIRE(h.tick() == TickOutcome::success);
    REQUIRE(h.last_rollup().size() == 1);
    const auto& r = h.last_rollup()[0];
    CHECK(r.product_key == "acme:reader");
    CHECK(r.vendor == "acme");  // registry values, not raw
    CHECK(r.title == "reader");
    CHECK(r.licensed_count == 2);
    CHECK(r.subscription_active_count == 3);
    CHECK(r.trial_count == 1);
    CHECK(r.expired_count == 1); // lapsed by the server-now rule
    CHECK(r.unknown_count == 1);
    CHECK(r.device_count == 4);                     // per-pair distinct sum
    CHECK(r.next_expiry_at == kNow0 + 10 * kDay);   // min FUTURE expiry
    CHECK(r.expiring_soon_count == 3);              // only the 10d rows
    CHECK(r.refreshed_at == kNow0);                 // the one cycle-wide now
}

// ── Sink containment ────────────────────────────────────────────────────────

TEST_CASE("a throwing sink is contained and counted; a failed arm still emits",
          "[sle][evaluator]") {
    EvalHarness h;
    seed_reader(h, "expired", 0);

    SECTION("sink throw -> delivery_failed, cycle survives, dedup armed") {
        h.sink_throws = true;
        REQUIRE(h.tick() == TickOutcome::success);
        CHECK(h.metrics.counter("yuzu_server_sle_alert_delivery_failed_total").value() == 1.0);
        CHECK(h.fired("expired") == 1.0);
        // Armed before delivery: the next tick holds down despite the throw.
        h.sink_throws = false;
        REQUIRE(h.tick() == TickOutcome::success);
        CHECK(h.emitted.empty());
    }
    SECTION("arm failure -> emit anyway (losing the alert is the worse failure)") {
        h.fail_upsert_alert_state = true;
        REQUIRE(h.tick() == TickOutcome::success);
        CHECK(h.emitted.size() == 1);
        // Unarmed: the next tick fires again — the bounded dedup-state-loss
        // burst, not silence.
        REQUIRE(h.tick() == TickOutcome::success);
        CHECK(h.emitted.size() == 2);
    }
}

// ── Thread lifecycle ────────────────────────────────────────────────────────

TEST_CASE("evaluator thread: immediate first tick, idempotent start, double stop, "
          "dtor joins, gauge seeded 0 first",
          "[sle][evaluator]") {
    EvalHarness h;
    seed_reader(h, "licensed", 0);
    auto deps = h.deps();
    deps.interval = std::chrono::seconds{3600};

    {
        LicenseComplianceEvaluator ev{std::move(deps)};
        ev.start();
        ev.start(); // idempotent
        // One immediate tick runs; poll briefly for it.
        for (int i = 0; i < 200 && h.replaced.empty(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        REQUIRE_FALSE(h.replaced.empty());
        // The liveness gauge exists (seeded 0 before the tick, then set on
        // success — either way the series exists, gov UP-2).
        CHECK(h.metrics.gauge("yuzu_server_sle_evaluator_last_success_timestamp").value() >=
              0.0);
        CHECK(h.metrics
                  .counter("yuzu_server_sle_evaluator_runs_total", {{"outcome", "success"}})
                  .value() >= 1.0);
        ev.stop();
        ev.stop(); // idempotent
    } // dtor joins (already stopped)

    const auto ticks = h.replaced.size();
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    CHECK(h.replaced.size() == ticks); // genuinely stopped
}

// ── End-to-end smoke over real stores ───────────────────────────────────────

TEST_CASE("evaluator end-to-end over real stores", "[pg][sle][evaluator]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    yuzu::server::SoftwareLicensingStore lic{pool};
    REQUIRE(lic.is_open());
    yuzu::server::ProductRegistryStore reg{pool};
    REQUIRE(reg.is_open());

    // Two agents' licence rows via the real ingest write.
    yuzu::server::AgentLicenseRow r1;
    r1.product = "Reader";
    r1.vendor = "Acme Inc";
    r1.license_type = "subscription";
    r1.state = "subscription_active";
    r1.expiry_at = kNow0 + 5 * kDay;
    r1.user_scope = "machine";
    yuzu::server::AgentLicenseRow r2 = r1;
    r2.state = "expired";
    r2.expiry_at = 0;
    REQUIRE(lic.replace_agent_licenses("agent-1", {r1}, "h1", "hash"));
    REQUIRE(lic.replace_agent_licenses("agent-2", {r1, r2}, "h2", "hash"));

    std::vector<SleAlert> emitted;
    LicenseComplianceEvaluator::Deps d;
    d.list_products = [&] { return reg.list_products(10000); };
    d.distinct_products = [&] { return lic.distinct_products(); };
    d.posture_inputs = [&] { return lic.posture_inputs(); };
    d.software_catalog = [&]() -> std::optional<std::vector<SoftwareCatalogRow>> {
        return std::vector<SoftwareCatalogRow>{}; // no inventory in this fixture
    };
    d.upsert_product = [&](std::string_view nk, std::string_view v, std::string_view t,
                           std::string_view e, std::string_view p) {
        return reg.upsert_product(nk, v, t, e, p);
    };
    d.upsert_alias = [&](std::string_view s, std::string_view rn, std::string_view rp,
                         std::int64_t id, std::string_view m, double c) {
        return reg.upsert_alias(s, rn, rp, id, m, c);
    };
    d.replace_posture_rollup = [&](const std::vector<LicensePostureRow>& rows,
                                   std::int64_t at) { return lic.replace_posture_rollup(rows, at); };
    d.alert_state = [&](std::string_view k, std::string_view kind) {
        return lic.alert_state(k, kind);
    };
    d.upsert_alert_state = [&](std::string_view k, std::string_view kind, std::string_view fp,
                               std::int64_t b, std::int64_t at) {
        return lic.upsert_alert_state(k, kind, fp, b, at);
    };
    d.on_alert = [&](const SleAlert& a) { emitted.push_back(a); };
    d.now_fn = [] { return kNow0; };

    LicenseComplianceEvaluator ev{std::move(d)};
    REQUIRE(ev.tick() == TickOutcome::success);

    // The rollup populated through the real store...
    auto rollup = lic.posture_rollup();
    REQUIRE(rollup.has_value());
    REQUIRE(rollup->size() == 1);
    CHECK((*rollup)[0].product_key == "acme:reader");
    CHECK((*rollup)[0].device_count == 2);
    CHECK((*rollup)[0].subscription_active_count == 2);
    CHECK((*rollup)[0].expired_count == 1);
    auto stamped = lic.posture_refreshed_at();
    REQUIRE(stamped.has_value());
    CHECK(*stamped == kNow0);
    // ...the registry gained the birthed product + the alias...
    auto products = reg.list_products(10);
    REQUIRE(products.has_value());
    REQUIRE(products->size() == 1);
    CHECK((*products)[0].norm_key == "acme:reader");
    // ...both conditions fired once...
    CHECK(emitted.size() == 2);
    // ...and a second tick fires nothing new (dedup persisted for real).
    REQUIRE(ev.tick() == TickOutcome::success);
    CHECK(emitted.size() == 2);
}
