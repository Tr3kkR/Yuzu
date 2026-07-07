/// @file sle_routes.cpp
/// `/api/v1/sle/*` read-route registration (ADR-0024, PR1a). See sle_routes.hpp
/// for the per-route auth posture. The handler chain mirrors the
/// `/api/v1/inventory/software` precedent EXACTLY: correlation id + header on
/// every path → auth/perm gate → 503-on-degrade (never an empty 200) → limit
/// clamp 1..1000 → audit; errors via the A4 envelope + `X-Correlation-Id`.
///
/// A4 / JSON helpers are re-implemented locally (small, self-contained) rather
/// than shared from rest_api_v1.cpp, whose `JObj`/`ok_json`/`error_json_a4` are
/// file-local (anonymous namespace / translation-unit `detail`) — the same
/// self-contained-route-file discipline InventoryRoutes follows with its own
/// `clamp_limit`. The wire shape (`{"error":{code,message,correlation_id,
/// retry_after_ms,...}},"meta":{"api_version":"v1"}}` and `{"data":...,"meta":
/// {"api_version":"v1"}}`) is kept byte-compatible with the A4 envelope.

#include "sle_routes.hpp"

#include "http_route_sink.hpp"
#include "rest_audit.hpp" // detail::try_persist_audit / emit_behavioral_audit (#1647)

// Shared full-page shell (defined at GLOBAL scope in guardian_page_ui.cpp).
extern const char* const kGuardianDetailPageHtml;

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

using nlohmann::json;

std::int64_t epoch_now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Upper bound on the `expiring_within_days` filter (~100 years). The filter
// computes `now + days*86400`; an unclamped value (std::stoll reaches ~9.2e18)
// would overflow int64 in that multiply/add — signed-overflow UB. 100 years is
// far past any real expiry horizon, so clamping here changes no legitimate query.
constexpr std::int64_t kMaxExpiringWithinDays = 36500;

/// grep-token correlation id, `req-<hex-ms>-<hex-seq>` — same shape as
/// rest_api_v1.cpp's make_correlation_id (echoed in X-Correlation-Id + every A4
/// body). Process-global monotonic sequence so two ids minted in the same ms differ.
std::string make_cid() {
    static std::atomic<std::uint64_t> seq{0};
    const auto t = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
    return std::format("req-{:x}-{:x}", static_cast<std::uint64_t>(t), seq.fetch_add(1));
}

/// A4 error envelope. retry_after_ms is ALWAYS a key (null unless set), per
/// docs/agentic-first-principle.md §A4; remediation/permission omitted when empty.
std::string a4_error(int code, std::string_view message, std::string_view cid,
                     std::optional<std::int64_t> retry_after_ms = std::nullopt,
                     std::string_view remediation = {}, std::string_view permission = {}) {
    // nlohmann::json takes std::string, not std::string_view, so materialise.
    json err;
    err["code"] = code;
    err["message"] = std::string(message);
    err["correlation_id"] = std::string(cid);
    if (retry_after_ms)
        err["retry_after_ms"] = *retry_after_ms;
    else
        err["retry_after_ms"] = nullptr;
    if (!remediation.empty())
        err["remediation"] = std::string(remediation);
    if (!permission.empty())
        err["permission"] = std::string(permission);
    json out;
    out["error"] = std::move(err);
    out["meta"] = json{{"api_version", "v1"}};
    return out.dump();
}

std::string ok_json(json data) {
    json out;
    out["data"] = std::move(data);
    out["meta"] = json{{"api_version", "v1"}};
    return out.dump();
}

void send_json(httplib::Response& res, int status, std::string body) {
    res.status = status;
    res.set_content(std::move(body), "application/json");
}

/// Clamp `limit` into [1, hi] in 64-bit BEFORE narrowing so a negative/wrapped
/// value can't defeat the cap (mirrors the /inventory/software REST route). A
/// non-integer value returns `dflt` (the query is lenient; the REST sibling 400s,
/// but the SLE reads follow the inventory-fragment lenient-clamp convention).
int clamp_limit(const httplib::Request& req, int dflt, int hi) {
    if (!req.has_param("limit"))
        return dflt;
    try {
        std::int64_t want = std::stoll(req.get_param_value("limit"));
        return static_cast<int>(std::clamp<std::int64_t>(want, 1, hi));
    } catch (...) {
        return dflt;
    }
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool icontains(const std::string& hay, const std::string& needle) {
    if (needle.empty())
        return true;
    return lower(hay).find(needle) != std::string::npos;
}

/// One parsed `probe_status|<surface>|ok|<rows>` / `probe_status|<surface>|
/// error|<reason>` line from the agent's `license_scan surfaces` output.
struct ParsedSurface {
    std::string surface;
    std::string status; ///< whitelisted to "ok" | "error"
    std::int64_t rows{0};
    std::string detail; ///< the error reason token (e.g. privilege_missing)
};

/// Parse the surfaces command output DEFENSIVELY: accept ONLY lines starting
/// `probe_status|` with a whitelisted status token; drop everything else.
/// This is also the guarantee that a hostile/buggy agent cannot reflect
/// `lic|` licence rows (which carry user_ref personal data) through the
/// unaudited-for-PII live route — non-probe_status lines never reach the
/// response. Returns nullopt when a NON-EMPTY output yields zero valid lines
/// (malformed device output → the caller 502s, never a false empty).
std::optional<std::vector<ParsedSurface>> parse_probe_status_lines(const std::string& output) {
    std::vector<ParsedSurface> out;
    std::size_t pos = 0;
    bool any_content = false;
    while (pos <= output.size()) {
        const std::size_t nl = output.find('\n', pos);
        std::string line = output.substr(pos, nl == std::string::npos ? std::string::npos
                                                                      : nl - pos);
        pos = nl == std::string::npos ? output.size() + 1 : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        any_content = true;
        // probe_status|<surface>|<status>|<rest>
        if (line.rfind("probe_status|", 0) != 0)
            continue;
        const std::size_t p1 = 13; // past "probe_status|"
        const std::size_t p2 = line.find('|', p1);
        if (p2 == std::string::npos)
            continue;
        const std::size_t p3 = line.find('|', p2 + 1);
        ParsedSurface s;
        s.surface = line.substr(p1, p2 - p1);
        s.status = p3 == std::string::npos ? line.substr(p2 + 1)
                                           : line.substr(p2 + 1, p3 - p2 - 1);
        if (s.surface.empty() || (s.status != "ok" && s.status != "error"))
            continue;
        const std::string rest = p3 == std::string::npos ? "" : line.substr(p3 + 1);
        if (s.status == "ok") {
            try {
                s.rows = std::stoll(rest);
            } catch (...) {
                s.rows = 0;
            }
        } else {
            s.detail = rest;
        }
        out.push_back(std::move(s));
    }
    if (any_content && out.empty())
        return std::nullopt; // malformed device output
    return out;
}

json posture_to_json(const LicensePostureRow& r) {
    json j;
    j["product_key"] = r.product_key;
    j["vendor"] = r.vendor;
    j["title"] = r.title;
    j["device_count"] = r.device_count;
    j["install_count"] = r.install_count;
    j["licensed"] = r.licensed_count;
    j["subscription_active"] = r.subscription_active_count;
    j["trial"] = r.trial_count;
    j["grace"] = r.grace_count;
    j["expired"] = r.expired_count;
    j["unlicensed"] = r.unlicensed_count;
    j["unknown"] = r.unknown_count;
    j["next_expiry_at"] = r.next_expiry_at;
    j["expiring_soon"] = r.expiring_soon_count;
    j["refreshed_at"] = r.refreshed_at;
    return j;
}

json agent_license_to_json(const AgentLicenseRow& r) {
    json j;
    j["product"] = r.product;
    j["vendor"] = r.vendor;
    j["version"] = r.version;
    j["license_type"] = r.license_type;
    j["state"] = r.state;
    j["expiry_at"] = r.expiry_at;
    j["channel"] = r.channel;
    j["key_hint"] = r.key_hint; // OS-provided partial only — never full key material
    j["detector"] = r.detector;
    j["confidence"] = r.confidence;
    j["exe_hints"] = r.exe_hints;
    // Personal data (ADR-0024 Decision 11): user_scope distinguishes per-user
    // detections; user_ref is the pseudonym (hash mode), raw name (collect), or
    // empty (omit) as minimised on-device. Rendering these is exactly why this
    // route is on the per-open behavioural-audit tier (G-2).
    j["user_scope"] = r.user_scope;
    j["user_ref"] = r.user_ref;
    j["collected_at"] = r.collected_at;
    j["first_seen"] = r.first_seen;
    j["last_seen"] = r.last_seen;
    return j;
}

} // namespace

namespace sle_detail {
// SLE-local live-dispatch seams (see the header). Defaults mirror the
// rest_api_v1 live seams: cap 4 (strictly below the worker pool), 40 polls ×
// 500 ms ≈ 20 s budget. NOTE: a WMI-degraded Windows host can legitimately
// take up to the plugin's 60 s enumeration deadline — such a host 504s
// honestly here (the stored drill stays available); do NOT raise the budget,
// it pins an httplib worker.
std::atomic<int>& sle_live_max_inflight() {
    static std::atomic<int> v{4};
    return v;
}
std::atomic<int>& sle_live_poll_max_polls() {
    static std::atomic<int> v{40};
    return v;
}
std::atomic<int>& sle_live_poll_interval_ms() {
    static std::atomic<int> v{500};
    return v;
}
} // namespace sle_detail

namespace {

/// RAII in-flight slot for the live surfaces dispatch (the rest_api_v1
/// LiveInflightGuard shape, SLE-local counter).
class SleLiveInflightGuard {
public:
    SleLiveInflightGuard() {
        const int cap = sle_detail::sle_live_max_inflight().load(std::memory_order_relaxed);
        acquired_ = count().fetch_add(1, std::memory_order_acq_rel) < cap;
        if (!acquired_)
            count().fetch_sub(1, std::memory_order_acq_rel);
    }
    ~SleLiveInflightGuard() {
        if (acquired_)
            count().fetch_sub(1, std::memory_order_acq_rel);
    }
    SleLiveInflightGuard(const SleLiveInflightGuard&) = delete;
    SleLiveInflightGuard& operator=(const SleLiveInflightGuard&) = delete;
    [[nodiscard]] bool acquired() const { return acquired_; }

private:
    static std::atomic<int>& count() {
        static std::atomic<int> v{0};
        return v;
    }
    bool acquired_{false};
};

} // namespace

bool sle_state_matches(const LicensePostureRow& r, const std::string& state) {
    if (state == "licensed")
        return r.licensed_count > 0;
    if (state == "subscription_active")
        return r.subscription_active_count > 0;
    if (state == "trial")
        return r.trial_count > 0;
    if (state == "grace")
        return r.grace_count > 0;
    if (state == "expired")
        return r.expired_count > 0;
    if (state == "unlicensed")
        return r.unlicensed_count > 0;
    if (state == "unknown")
        return r.unknown_count > 0;
    if (state == "lapsed")
        return (r.expired_count + r.unlicensed_count) > 0;
    return false;
}

SlePostureAggregates sle_aggregate_posture(const std::vector<LicensePostureRow>& rollup) {
    SlePostureAggregates agg;
    agg.products = static_cast<std::int64_t>(rollup.size());
    for (const auto& r : rollup) {
        agg.installs += r.install_count;
        if ((r.expired_count + r.unlicensed_count) > 0)
            ++agg.lapsed_products;
        agg.expiring_soon += r.expiring_soon_count;
        agg.as_of = std::max(agg.as_of, r.refreshed_at);
        if (r.next_expiry_at > 0 &&
            (agg.next_expiry_at == 0 || r.next_expiry_at < agg.next_expiry_at))
            agg.next_expiry_at = r.next_expiry_at;
    }
    agg.evaluated = agg.as_of > 0;
    return agg;
}

void sle_apply_posture_meta(SlePostureAggregates& agg, std::int64_t refreshed_at) {
    agg.as_of = refreshed_at;
    agg.evaluated = refreshed_at > 0;
}

void SleRoutes::register_routes(httplib::Server& svr, PermFn perm_fn, ScopedPermFn scoped_perm_fn,
                                PostureFn posture_fn, LicenseDevicesFn devices_fn,
                                AgentLicensesFn agent_licenses_fn, AuditFn audit_fn,
                                PostureMetaFn posture_meta_fn, UserRefModeFn user_ref_mode_fn,
                                DispatchFn dispatch_fn, ResponsesFn responses_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(perm_fn), std::move(scoped_perm_fn), std::move(posture_fn),
                    std::move(devices_fn), std::move(agent_licenses_fn), std::move(audit_fn),
                    std::move(posture_meta_fn), std::move(user_ref_mode_fn),
                    std::move(dispatch_fn), std::move(responses_fn));
}

void SleRoutes::register_routes(HttpRouteSink& sink, PermFn perm_fn, ScopedPermFn scoped_perm_fn,
                                PostureFn posture_fn, LicenseDevicesFn devices_fn,
                                AgentLicensesFn agent_licenses_fn, AuditFn audit_fn,
                                PostureMetaFn posture_meta_fn, UserRefModeFn user_ref_mode_fn,
                                DispatchFn dispatch_fn, ResponsesFn responses_fn) {
    perm_fn_ = std::move(perm_fn);
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    posture_fn_ = std::move(posture_fn);
    devices_fn_ = std::move(devices_fn);
    agent_licenses_fn_ = std::move(agent_licenses_fn);
    audit_fn_ = std::move(audit_fn);
    posture_meta_fn_ = std::move(posture_meta_fn);
    user_ref_mode_fn_ = std::move(user_ref_mode_fn);
    dispatch_fn_ = std::move(dispatch_fn);
    responses_fn_ = std::move(responses_fn);

    // ── GET /api/v1/sle/summary — fleet posture headline (GLOBAL SoftwareLicensing:Read) ──
    // Reads the precomputed posture rollup and derives honest aggregates. In PR1a
    // the rollup is empty (the PR1b evaluator populates it), so this returns an
    // honest empty shape (as_of=0, evaluated=false, zero counts) — NOT a fabricated
    // zero and NOT a silent-empty degrade (a degrade is a 503 below). Aggregate,
    // machine-scope headline (no user_ref) → SET-AND-PROCEED audit (try_persist_audit).
    sink.Get("/api/v1/sle/summary", [this](const httplib::Request& req, httplib::Response& res) {
        const auto cid = make_cid();
        res.set_header("X-Correlation-Id", cid);
        if (!perm_fn_) {
            send_json(res, 503, a4_error(503, "authorization gate not configured", cid));
            return;
        }
        if (!perm_fn_(req, res, "SoftwareLicensing", "Read"))
            return; // perm_fn wrote 401/403/503 (fail-closed on corrupt rbac.db per G-1)

        std::optional<std::vector<LicensePostureRow>> rollup;
        if (posture_fn_)
            rollup = posture_fn_();
        if (!rollup) {
            // Store/pool/query degrade — NEVER a fabricated empty summary (an empty
            // compliance headline reads as "nothing detected / nothing lapsed").
            (void)detail::try_persist_audit(audit_fn_, req, "sle.summary", "failure",
                                            "SoftwareLicensing", "fleet",
                                            "posture rollup degraded; cid=" + cid);
            send_json(res, 503,
                      a4_error(503, "SLE posture rollup unavailable — read failed", cid, 5000,
                               "retry the request"));
            return;
        }

        SlePostureAggregates agg = sle_aggregate_posture(*rollup);
        // The first-class posture meta stamp (G-4, license_posture_meta) is
        // authoritative for as_of/evaluated when wired: it distinguishes an
        // evaluated-but-empty estate (stamp > 0, zero rows) from a never-run
        // one. A degraded stamp read is a 503 like the rollup itself — never
        // a false "never evaluated". Unwired (older tests) → the row-derived
        // fallback above.
        if (posture_meta_fn_) {
            const auto stamp = posture_meta_fn_();
            if (!stamp) {
                (void)detail::try_persist_audit(audit_fn_, req, "sle.summary", "failure",
                                                "SoftwareLicensing", "fleet",
                                                "posture meta degraded; cid=" + cid);
                send_json(res, 503,
                          a4_error(503, "SLE posture rollup unavailable — read failed", cid, 5000,
                                   "retry the request"));
                return;
            }
            sle_apply_posture_meta(agg, *stamp);
        }
        json data;
        data["as_of"] = agg.as_of;
        data["evaluated"] = agg.evaluated;
        data["products"] = agg.products;
        data["installs"] = agg.installs;
        data["lapsed_products"] = agg.lapsed_products;
        data["expiring_soon"] = agg.expiring_soon;
        data["next_expiry_at"] = agg.next_expiry_at;

        (void)detail::try_persist_audit(
            audit_fn_, req, "sle.summary", "success", "SoftwareLicensing", "fleet",
            "products=" + std::to_string(rollup->size()) + " cid=" + cid);
        send_json(res, 200, ok_json(std::move(data)));
    });

    // ── GET /api/v1/sle/licenses?state=&expiring_within_days=&q=&limit= ──
    // Fleet posture rows (GLOBAL SoftwareLicensing:Read), filtered then capped
    // 1..1000. Global-gated aggregate (pinned global-only per ADR-0017 / Decision
    // 10): a group-confined principal is denied at the global gate, never served a
    // partial rollup. Empty until the PR1b evaluator populates the rollup.
    sink.Get("/api/v1/sle/licenses", [this](const httplib::Request& req, httplib::Response& res) {
        const auto cid = make_cid();
        res.set_header("X-Correlation-Id", cid);
        if (!perm_fn_) {
            send_json(res, 503, a4_error(503, "authorization gate not configured", cid));
            return;
        }
        if (!perm_fn_(req, res, "SoftwareLicensing", "Read"))
            return;

        std::optional<std::vector<LicensePostureRow>> rollup;
        if (posture_fn_)
            rollup = posture_fn_();
        if (!rollup) {
            (void)detail::try_persist_audit(audit_fn_, req, "sle.licenses.query", "failure",
                                            "SoftwareLicensing", "fleet",
                                            "posture rollup degraded; cid=" + cid);
            send_json(res, 503,
                      a4_error(503, "SLE posture rollup unavailable — read failed", cid, 5000,
                               "retry the request"));
            return;
        }

        const std::string state = req.has_param("state") ? req.get_param_value("state") : "";
        const std::string q = req.has_param("q") ? lower(req.get_param_value("q")) : "";
        std::int64_t expiring_days = -1; // -1 = no expiry filter
        if (req.has_param("expiring_within_days")) {
            try {
                // Clamp to [0, kMaxExpiringWithinDays] BEFORE the days*86400 multiply
                // below — an unclamped value overflows int64 (signed-overflow UB). A
                // negative clamps to 0 (filter active, today-only), preserving the
                // prior std::max(0, …) behaviour.
                expiring_days = std::clamp<std::int64_t>(
                    std::stoll(req.get_param_value("expiring_within_days")), 0,
                    kMaxExpiringWithinDays);
            } catch (...) {
                expiring_days = -1; // non-integer → no filter (lenient)
            }
        }
        const int limit = clamp_limit(req, 200, 1000);
        const std::int64_t now = epoch_now_secs();

        json licenses = json::array();
        std::int64_t as_of = 0;
        std::int64_t matched = 0;
        bool hit_cap = false;
        for (const auto& r : *rollup) {
            as_of = std::max(as_of, r.refreshed_at);
            if (!state.empty() && !sle_state_matches(r, state))
                continue;
            if (expiring_days >= 0 &&
                !(r.next_expiry_at > 0 && r.next_expiry_at <= now + expiring_days * 86400))
                continue;
            if (!q.empty() && !(icontains(r.title, q) || icontains(r.vendor, q) ||
                                icontains(r.product_key, q)))
                continue;
            ++matched;
            if (static_cast<int>(licenses.size()) >= limit) {
                hit_cap = true; // more match than the page holds
                continue;
            }
            licenses.push_back(posture_to_json(r));
        }

        (void)detail::try_persist_audit(
            audit_fn_, req, "sle.licenses.query", "success", "SoftwareLicensing",
            state.empty() ? "fleet" : ("state=" + state),
            "rows=" + std::to_string(licenses.size()) + " cid=" + cid);

        json data;
        data["licenses"] = std::move(licenses);
        data["count"] = matched;
        data["as_of"] = as_of;
        if (hit_cap)
            data["result_truncated_by_cap"] = true;
        send_json(res, 200, ok_json(std::move(data)));
    });

    // ── GET /api/v1/sle/licenses/{key}/devices — fan-out list (GLOBAL-gated) ──
    // ADR-0017 PR-A FLIP-WAVE CONSUMER (#1634 umbrella checklist; #1715 deny-precedence
    // prerequisite): a true fan-out list read that CANNOT admit-then-filter under the
    // current global gate, so it ships GLOBAL-gated on SoftwareLicensing:Read and is
    // registered here (code) + on the ADR-0017 ladder (docs step) as a flip consumer.
    // The admit-then-filter chokepoint and its "filters BEFORE the LIMIT" completeness
    // test land AT THE FLIP, NOT in PR1a (roadmap §3.5 / D-4 / test matrix). PR1a wires
    // an honest-empty provider (the per-device posture breakdown is PR1b).
    sink.Get(R"(/api/v1/sle/licenses/([^/]+)/devices)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = make_cid();
                 res.set_header("X-Correlation-Id", cid);
                 const std::string key = req.matches.size() > 1 ? req.matches[1].str() : "";
                 if (!perm_fn_) {
                     send_json(res, 503, a4_error(503, "authorization gate not configured", cid));
                     return;
                 }
                 if (!perm_fn_(req, res, "SoftwareLicensing", "Read"))
                     return;

                 const int limit = clamp_limit(req, 200, 1000);
                 std::optional<std::vector<SleLicenseDeviceRow>> rows;
                 if (devices_fn_)
                     rows = devices_fn_(key, limit);
                 if (!rows) {
                     (void)detail::try_persist_audit(audit_fn_, req, "sle.licenses.devices",
                                                     "failure", "SoftwareLicensing", "key=" + key,
                                                     "fan-out read degraded; cid=" + cid);
                     send_json(res, 503,
                               a4_error(503, "SLE licence device list unavailable — read failed",
                                        cid, 5000, "retry the request"));
                     return;
                 }

                 const bool hit_cap = static_cast<int>(rows->size()) >= limit;
                 json devices = json::array();
                 for (const auto& d : *rows) {
                     json j;
                     j["agent_id"] = d.agent_id;
                     j["hostname"] = d.hostname;
                     j["state"] = d.state;
                     j["expiry_at"] = d.expiry_at;
                     devices.push_back(std::move(j));
                 }
                 (void)detail::try_persist_audit(
                     audit_fn_, req, "sle.licenses.devices", "success", "SoftwareLicensing",
                     "key=" + key, "rows=" + std::to_string(devices.size()) + " cid=" + cid);

                 json data;
                 data["product_key"] = key;
                 data["devices"] = std::move(devices);
                 data["count"] = static_cast<std::int64_t>(rows->size());
                 if (hit_cap)
                     data["result_truncated_by_cap"] = true;
                 send_json(res, 200, ok_json(std::move(data)));
             });

    // ── GET /api/v1/sle/agents/{agent_id} — single-agent DRILL (scoped + fail-closed audit) ──
    // Decision 10/11 + roadmap D-4/G-2: takes the WORKING ancestor-aware per-device
    // scoped gate day one (SoftwareLicensing:Read + agent scope; 403 outside scope),
    // the device_routes precedent. Renders per-agent detected licences INCLUDING
    // user_scope/user_ref (personal data), so it joins the per-open behavioural-audit
    // tier (emit_behavioral_audit, dex.device.view convention) and FAILS CLOSED (503 +
    // Sec-Audit-Failed) if the access-audit row cannot persist — the device's licence
    // PII is never served without durable evidence (SOC 2 CC7.2). REAL data in PR1a.
    sink.Get(R"(/api/v1/sle/agents/([^/]+))",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = make_cid();
                 res.set_header("X-Correlation-Id", cid);
                 const std::string agent_id = req.matches.size() > 1 ? req.matches[1].str() : "";

                 // Per-device scope is MANDATORY — fail CLOSED if the gate is unwired
                 // rather than silently widening to a global read (mirrors the dex
                 // per-device REST route; production always wires it from server.cpp).
                 if (!scoped_perm_fn_) {
                     send_json(res, 503, a4_error(503, "scope gate not configured", cid));
                     return;
                 }
                 if (!scoped_perm_fn_(req, res, "SoftwareLicensing", "Read", agent_id))
                     return; // the gate wrote its own 401/403

                 // Audit-on-open FAIL-CLOSED for this PII read (G-2): refuse to serve the
                 // agent's licence rows when the evidence row is KNOWN to have failed to
                 // persist. A null audit_fn is audit-off (not a failure) → serves, per the
                 // AuditFn contract. Set BEFORE the store read (per-open, not per-row).
                 if (!detail::emit_behavioral_audit(
                         audit_fn_, req, res, "sle.agent.view", "success", "Agent", agent_id,
                         "SLE per-agent detected-licence drill (renders user_scope/user_ref) cid=" +
                             cid)) {
                     send_json(res, 503,
                               a4_error(503,
                                        "audit subsystem unavailable; refusing to serve per-agent "
                                        "licence data without durable evidence",
                                        cid, 5000, "retry the request"));
                     spdlog::warn("sle.agent.view audit fail-closed (503) cid={} agent_id={}", cid,
                                  agent_id);
                     return;
                 }

                 std::optional<std::vector<AgentLicenseRow>> rows;
                 if (agent_licenses_fn_)
                     rows = agent_licenses_fn_(agent_id);
                 if (!rows) {
                     send_json(res, 503,
                               a4_error(503, "detected-licence store unavailable — read failed", cid,
                                        5000, "retry the request"));
                     return;
                 }

                 json licenses = json::array();
                 for (const auto& r : *rows)
                     licenses.push_back(agent_license_to_json(r));
                 json data;
                 data["agent_id"] = agent_id;
                 data["licenses"] = std::move(licenses);
                 data["count"] = static_cast<std::int64_t>(rows->size());
                 // D-10 read-back: the effective user-ref mode as the device's
                 // LAST STORED blob declared it ("collect"|"hash"|"omit"; null =
                 // never synced this source) — the operator's verification that
                 // a --license-scan-user-ref knob flip landed. Same store, same
                 // authoritative posture: a degraded read is the drill's 503,
                 // never a fabricated null.
                 if (user_ref_mode_fn_) {
                     auto mode = user_ref_mode_fn_(agent_id);
                     if (!mode) {
                         send_json(res, 503,
                                   a4_error(503,
                                            "detected-licence store unavailable — read failed",
                                            cid, 5000, "retry the request"));
                         return;
                     }
                     if (mode->has_value())
                         data["effective_user_ref_mode"] = **mode;
                     else
                         data["effective_user_ref_mode"] = nullptr;
                 }
                 send_json(res, 200, ok_json(std::move(data)));
             });

    // ── POST /api/v1/sle/agents/{agent_id}/surfaces — LIVE surface diagnostics (D-10) ──
    // The flappy per-surface diagnostics are LIVE-ONLY (ADR-0024 Decision 10):
    // this dispatches the agent's `license_scan surfaces` action over the
    // command path and returns the parsed probe_status lines — which detection
    // surfaces ran, how many rows each yielded, and the failure reason token
    // (e.g. privilege_missing) for the ones that didn't. POST, not GET: the
    // handler dispatches a real command to the device (the dex-live
    // architect-B1 precedent, test-locked there). The agent-side action ships
    // with the plugin and emits ONLY probe_status lines — per-user outcomes
    // aggregate per surface, so no profile name / user_ref / SID can appear —
    // and the whitelist parser below makes that a served guarantee, not a
    // trust assumption: non-probe_status lines (e.g. a hostile `lic|` row that
    // would otherwise reflect user_ref through this route) never reach the
    // response.
    //
    // GATES: the drill's per-device scoped SoftwareLicensing:Read AND
    // Execution:Execute (everything that dispatches gates Execute — the
    // dex-live / /api/command posture), both fail-closed when unwired.
    // AUDIT: set-and-proceed `sle.agent.surfaces` BEFORE dispatch. This is
    // deliberately NOT the drill's fail-closed behavioural tier (G-2): that
    // tier binds to rendering individual-identifying data, and the surfaces
    // payload carries none (reason tokens only, verified end-to-end +
    // enforced by the parser); the posture matches preflight's machine-health
    // reads. The daily sync runs the identical collection unaudited.
    sink.Post(
        R"(/api/v1/sle/agents/([^/]+)/surfaces)",
        [this](const httplib::Request& req, httplib::Response& res) {
            const auto cid = make_cid();
            res.set_header("X-Correlation-Id", cid);
            const std::string agent_id = req.matches.size() > 1 ? req.matches[1].str() : "";
            if (!scoped_perm_fn_) {
                send_json(res, 503, a4_error(503, "scope gate not configured", cid));
                return;
            }
            if (!scoped_perm_fn_(req, res, "SoftwareLicensing", "Read", agent_id))
                return;
            if (!scoped_perm_fn_(req, res, "Execution", "Execute", agent_id))
                return;
            if (!dispatch_fn_ || !responses_fn_) {
                send_json(res, 503,
                          a4_error(503, "live surface diagnostics unavailable", cid, 5000));
                return;
            }
            SleLiveInflightGuard slot;
            if (!slot.acquired()) {
                send_json(res, 429,
                          a4_error(429, "too many concurrent live queries; retry shortly", cid,
                                   2000, "retry the request"));
                return;
            }
            (void)detail::try_persist_audit(audit_fn_, req, "sle.agent.surfaces", "requested",
                                            "Agent", agent_id,
                                            "live surface diagnostics dispatch cid=" + cid);
            const auto [command_id, sent] =
                dispatch_fn_("license_scan", "surfaces", {agent_id}, "", {}, "");
            if (sent == 0) {
                send_json(res, 503,
                          a4_error(503,
                                   "device offline — live surface diagnostics need a "
                                   "connected agent",
                                   cid, 5000));
                return;
            }
            const int max_polls =
                sle_detail::sle_live_poll_max_polls().load(std::memory_order_relaxed);
            const auto interval = std::chrono::milliseconds(
                sle_detail::sle_live_poll_interval_ms().load(std::memory_order_relaxed));
            // Cap the device output we parse (a runaway agent must not make a
            // worker hold a multi-MB blob); surfaces output is tiny by design.
            constexpr std::size_t kMaxSurfacesOutputBytes = 64 * 1024;
            for (int i = 0; i < max_polls; ++i) {
                if (i > 0)
                    std::this_thread::sleep_for(interval); // query first; back off on miss
                auto rows = responses_fn_(command_id);
                if (!rows) {
                    send_json(res, 503,
                              a4_error(503, "response store unavailable — read failed", cid,
                                       5000, "retry the request"));
                    return;
                }
                std::string output, error_detail;
                int terminal = -1;
                bool have_output = false;
                for (const auto& r : *rows) {
                    if (r.agent_id != agent_id)
                        continue; // never render another agent's row
                    if (!r.output.empty()) {
                        output = r.output;
                        have_output = true;
                    }
                    if (r.status >= 1) {
                        terminal = r.status;
                        error_detail = r.error_detail;
                    }
                }
                // FAILURE WINS: a terminal-failure row 502s even alongside a
                // partial-output row (a failed command must not read as data).
                if (terminal >= 2) {
                    send_json(res, 502,
                              a4_error(502,
                                       "device query failed: " + error_detail.substr(0, 200),
                                       cid));
                    return;
                }
                if (have_output) {
                    if (output.rfind("error|", 0) == 0) {
                        send_json(res, 502,
                                  a4_error(502,
                                           "device reported an error: " + output.substr(6, 200),
                                           cid));
                        return;
                    }
                    if (output.size() > kMaxSurfacesOutputBytes) {
                        send_json(res, 502, a4_error(502, "device output too large", cid));
                        return;
                    }
                    const auto parsed = parse_probe_status_lines(output);
                    if (!parsed) {
                        send_json(res, 502, a4_error(502, "malformed device output", cid));
                        return;
                    }
                    json surfaces = json::array();
                    for (const auto& s : *parsed) {
                        json j;
                        j["surface"] = s.surface;
                        j["status"] = s.status;
                        if (s.status == "ok")
                            j["rows"] = s.rows;
                        else
                            j["detail"] = s.detail;
                        surfaces.push_back(std::move(j));
                    }
                    json data;
                    data["agent_id"] = agent_id;
                    data["live"] = true;
                    data["as_of"] = epoch_now_secs();
                    data["count"] = static_cast<std::int64_t>(surfaces.size());
                    data["surfaces"] = std::move(surfaces);
                    send_json(res, 200, ok_json(std::move(data)));
                    return;
                }
                if (terminal == 1) {
                    // Success terminal with no output: honest empty (not a 504).
                    json data;
                    data["agent_id"] = agent_id;
                    data["live"] = true;
                    data["as_of"] = epoch_now_secs();
                    data["count"] = 0;
                    data["surfaces"] = json::array();
                    send_json(res, 200, ok_json(std::move(data)));
                    return;
                }
            }
            send_json(res, 504,
                      a4_error(504, "device did not respond in time", cid, 3000,
                               "retry the request"));
        });
}

void SleRoutes::register_page_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                     PostureFn posture_fn, PostureMetaFn posture_meta_fn,
                                     AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_page_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(posture_fn),
                         std::move(posture_meta_fn), std::move(audit_fn));
}

void SleRoutes::register_page_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                     PostureFn posture_fn, PostureMetaFn posture_meta_fn,
                                     AuditFn audit_fn) {
    page_auth_fn_ = std::move(auth_fn);
    page_perm_fn_ = std::move(perm_fn);
    page_posture_fn_ = std::move(posture_fn);
    page_meta_fn_ = std::move(posture_meta_fn);
    page_audit_fn_ = std::move(audit_fn);

    // ── GET /sle — the page shell (auth-only static chrome; data gates on the fragment) ──
    // Clones the /inventory page exactly: the shared guardian shell + token
    // substitution + the Guardian-off / SLE-on active-nav swap (the SLE link
    // exists in the shell nav since the PR1b nav sweep).
    sink.Get("/sle", [this](const httplib::Request& req, httplib::Response& res) {
        if (!page_auth_fn_) {
            res.status = 503;
            return;
        }
        auto session = page_auth_fn_(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        std::string html(kGuardianDetailPageHtml);
        auto sub = [&](const std::string& tok, const std::string& val) {
            for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
                html.replace(p, tok.size(), val);
        };
        sub("{{TITLE}}", "Yuzu \xE2\x80\x94 SLE");
        sub("{{FRAGMENT}}", "/fragments/sle/licenses");
        // Mark the SLE nav item active, Guardian (the shell default) inactive.
        sub("<a href=\"/guardian\" class=\"nav-link active\">Guardian</a>",
            "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>");
        sub("<a href=\"/sle\" class=\"nav-link\">SLE</a>",
            "<a href=\"/sle\" class=\"nav-link active\">SLE</a>");
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(std::move(html), "text/html; charset=utf-8");
    });

    // ── GET /fragments/sle/licenses — the Licences view (SoftwareLicensing:Read) ──
    // Server-rendered posture table + KPI tiles (D-7: tables + tiles only, no
    // charts). Filter semantics mirror the REST /sle/licenses route exactly
    // (sle_state_matches / case-insensitive q / expiring window / limit clamp);
    // the KPI tiles aggregate the UNFILTERED rollup + the G-4 meta stamp so a
    // filter never shrinks the headline. Machine-scope aggregate (no user_ref)
    // → set-and-proceed audit, the inventory.software.catalog tier.
    sink.Get("/fragments/sle/licenses",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!page_perm_fn_) {
                     res.status = 503;
                     return;
                 }
                 if (!page_perm_fn_(req, res, "SoftwareLicensing", "Read"))
                     return; // the gate wrote 401/403/503 (fail-closed, G-1)

                 const std::string state =
                     req.has_param("state") ? req.get_param_value("state") : "";
                 const std::string q = req.has_param("q") ? lower(req.get_param_value("q")) : "";
                 std::int64_t expiring_days = -1;
                 if (req.has_param("expiring_within_days")) {
                     try {
                         expiring_days = std::clamp<std::int64_t>(
                             std::stoll(req.get_param_value("expiring_within_days")), 0,
                             kMaxExpiringWithinDays);
                     } catch (...) {
                         expiring_days = -1;
                     }
                 }
                 const int limit = clamp_limit(req, 200, 1000);
                 const std::int64_t now = epoch_now_secs();

                 std::optional<std::vector<LicensePostureRow>> rollup;
                 if (page_posture_fn_)
                     rollup = page_posture_fn_();

                 SlePostureAggregates agg;
                 bool meta_degraded = false;
                 if (rollup) {
                     agg = sle_aggregate_posture(*rollup);
                     if (page_meta_fn_) {
                         const auto stamp = page_meta_fn_();
                         if (stamp)
                             sle_apply_posture_meta(agg, *stamp);
                         else
                             meta_degraded = true; // treat as a store degrade below
                     }
                 }

                 std::optional<std::vector<LicensePostureRow>> filtered;
                 bool capped = false;
                 if (rollup && !meta_degraded) {
                     filtered.emplace();
                     for (const auto& r : *rollup) {
                         if (!state.empty() && !sle_state_matches(r, state))
                             continue;
                         if (expiring_days >= 0 &&
                             !(r.next_expiry_at > 0 &&
                               r.next_expiry_at <= now + expiring_days * 86400))
                             continue;
                         if (!q.empty() && !(icontains(r.title, q) || icontains(r.vendor, q) ||
                                             icontains(r.product_key, q)))
                             continue;
                         if (static_cast<int>(filtered->size()) >= limit) {
                             capped = true;
                             break;
                         }
                         filtered->push_back(r);
                     }
                 }

                 (void)detail::try_persist_audit(
                     page_audit_fn_, req, "sle.licenses.view", filtered ? "success" : "failure",
                     "SoftwareLicensing", state.empty() ? "fleet" : ("state=" + state),
                     filtered ? ("rows=" + std::to_string(filtered->size()))
                              : "posture rollup degraded");

                 res.set_content(render_sle_licenses_fragment(filtered, agg, state,
                                                              req.has_param("q")
                                                                  ? req.get_param_value("q")
                                                                  : "",
                                                              expiring_days, capped, now),
                                 "text/html; charset=utf-8");
             });
}

} // namespace yuzu::server
