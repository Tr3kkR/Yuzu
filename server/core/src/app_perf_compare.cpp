#include "app_perf_compare.hpp"

#include "dex_perf_model.hpp" // kDexCohortFloor

#include <algorithm>
#include <cmath>
#include <map>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

/// Sanitise a CPU% value at the scalar boundary: NaN/Inf → 0, and clamp to the
/// valid [0, 100] share-of-machine-capacity range. The B1 store clamps `cpu_avg`
/// finite + ≤100 at ingest, so this is unreachable through the authenticated
/// agent→B1→reader chain TODAY — but `compare()` is documented as the seam a future
/// LIVE candidate (fan-out procperf) feeds directly, bypassing the store clamp. A
/// NaN reaching either `std::sort` below would be undefined behaviour (NaN breaks
/// strict-weak ordering → OOB read), and a finite-but-out-of-range value (e.g.
/// 1e300) would blow the means/percentiles. Sanitising here closes both independent
/// of the upstream writer (gov 2026-06-30, convergent finding across reviewers).
///
/// `ws_avg_bytes` is deliberately NOT given a sibling clamp: it is `int64`, so it
/// cannot be NaN/Inf (no sort-UB to close), and there is no principled byte ceiling
/// for a working set (the store's ingest clamp at 2^50 already bounds the persisted
/// value). The asymmetry is intentional, not an oversight (gov round-2 INFO).
double sanitize_cpu(double v) { return std::isfinite(v) ? std::clamp(v, 0.0, 100.0) : 0.0; }

/// PURE: the p-th percentile (p in [0,1]) of a scalar sample by the platform
/// nearest-rank DIRECTION — rank `r = ceil(p·n)`, clamped to `[1, n]`, value of
/// the r-th smallest element. Matches `detail::nearest_rank` /
/// `percentile_from_hist` so every perf surface reads percentiles the same way.
/// Empty → 0 (the callers only invoke it on a non-empty paired set).
template <typename T> T scalar_percentile(std::vector<T> v, double p) {
    if (v.empty())
        return T{};
    std::sort(v.begin(), v.end());
    p = std::clamp(p, 0.0, 1.0);
    auto r = static_cast<std::int64_t>(std::ceil(p * static_cast<double>(v.size())));
    r = std::clamp<std::int64_t>(r, 1, static_cast<std::int64_t>(v.size()));
    return v[static_cast<std::size_t>(r - 1)];
}

double mean(const std::vector<double>& v) {
    if (v.empty())
        return 0.0;
    double s = 0.0;
    for (const double x : v)
        s += x;
    return s / static_cast<double>(v.size());
}

std::int64_t mean_i64(const std::vector<std::int64_t>& v) {
    if (v.empty())
        return 0;
    double s = 0.0; // accumulate in double — robust to a large cohort × large ws
    for (const std::int64_t x : v)
        s += static_cast<double>(x);
    return static_cast<std::int64_t>(std::llround(s / static_cast<double>(v.size())));
}

} // namespace

std::vector<MachineVersionScalar> reduce_version_window(const std::vector<AppPerfCohortRow>& rows,
                                                        std::string_view version, int window_days) {
    if (window_days <= 0)
        window_days = 1;

    // Group this version's rows by machine. std::map (ordered) → deterministic
    // output order independent of input order; the cohort is bounded.
    std::map<std::string, std::vector<const AppPerfCohortRow*>> by_agent;
    for (const AppPerfCohortRow& r : rows) {
        if (r.version != version)
            continue;
        by_agent[r.agent_id].push_back(&r);
    }

    std::vector<MachineVersionScalar> out;
    out.reserve(by_agent.size());
    for (auto& [agent_id, recs] : by_agent) {
        // Most recent `window_days` days this machine ran the version (B1 is one
        // row per (agent, version, day), so distinct days == rows). Anchored to
        // the machine's OWN days, never to `today`.
        std::sort(recs.begin(), recs.end(),
                  [](const AppPerfCohortRow* a, const AppPerfCohortRow* b) { return a->day > b->day; });
        const std::size_t take = std::min<std::size_t>(recs.size(), static_cast<std::size_t>(window_days));

        double cpu_ws = 0.0, ws_ws = 0.0; // sample-weighted sums
        std::int64_t samples = 0;
        for (std::size_t i = 0; i < take; ++i) {
            const AppPerfCohortRow& r = *recs[i];
            const double w = static_cast<double>(r.samples > 0 ? r.samples : 0);
            cpu_ws += sanitize_cpu(r.cpu_avg) * w; // NaN/Inf→0, clamp [0,100] (sort-UB + range)
            ws_ws += static_cast<double>(r.ws_avg_bytes) * w;
            samples += (r.samples > 0 ? r.samples : 0);
        }

        // A machine whose entire in-window history for this version has ZERO samples
        // measured nothing — it carries no real scalar, so it is EXCLUDED (not paired
        // on noise). Without a cohort floor, one zero-sample canary would otherwise
        // swing the median/distribution with a full equal vote (gov UP-3). It will
        // read as having no data for this version (→ baseline_only/candidate_only or
        // no_data), which is the honest answer: we have no measurement for it.
        if (samples <= 0)
            continue;

        MachineVersionScalar m;
        m.agent_id = agent_id;
        m.samples = samples;
        m.day_count = static_cast<std::int64_t>(take);
        m.cpu = cpu_ws / static_cast<double>(samples);
        m.ws = static_cast<std::int64_t>(std::llround(ws_ws / static_cast<double>(samples)));
        out.push_back(std::move(m));
    }
    return out;
}

PairedComparison compare(const std::vector<MachineVersionScalar>& baseline,
                         const std::vector<MachineVersionScalar>& candidate,
                         std::string_view baseline_version, std::string_view candidate_version,
                         int window_days) {
    PairedComparison out;
    out.baseline_version = std::string(baseline_version);
    out.candidate_version = std::string(candidate_version);
    out.window_days = window_days;

    // Index candidate by agent_id (first occurrence wins — defence; the reducer
    // already yields one per machine). `seen_candidate` tracks which candidate
    // machines paired, so the leftovers are `candidate_only`.
    std::unordered_map<std::string, const MachineVersionScalar*> cand_by_agent;
    cand_by_agent.reserve(candidate.size());
    for (const MachineVersionScalar& c : candidate)
        cand_by_agent.emplace(c.agent_id, &c);

    std::vector<double> cpu_before, cpu_after, cpu_delta;
    std::vector<std::int64_t> ws_before, ws_after, ws_delta;
    std::unordered_map<std::string, bool> baseline_keys;
    baseline_keys.reserve(baseline.size());

    for (const MachineVersionScalar& b : baseline) {
        if (!baseline_keys.emplace(b.agent_id, true).second)
            continue; // duplicate baseline machine — first wins
        auto it = cand_by_agent.find(b.agent_id);
        if (it == cand_by_agent.end()) {
            ++out.baseline_only;
            continue;
        }
        const MachineVersionScalar& c = *it->second;
        MachinePair p;
        p.agent_id = b.agent_id;
        // Sanitise at the scalar boundary: a LIVE candidate (slice 2) feeds these
        // scalars to compare() directly, bypassing the B1 store's NaN clamp; a
        // non-finite cpu would make the cpu_delta sort below UB.
        const double cb = sanitize_cpu(b.cpu);
        const double ca = sanitize_cpu(c.cpu);
        p.cpu_before = cb;
        p.cpu_after = ca;
        p.cpu_delta = ca - cb;
        p.ws_before = b.ws;
        p.ws_after = c.ws;
        p.ws_delta = c.ws - b.ws;
        p.samples = std::min(b.samples, c.samples);

        cpu_before.push_back(p.cpu_before);
        cpu_after.push_back(p.cpu_after);
        cpu_delta.push_back(p.cpu_delta);
        ws_before.push_back(p.ws_before);
        ws_after.push_back(p.ws_after);
        ws_delta.push_back(p.ws_delta);

        if (p.cpu_delta > kCpuFlatBandPp)
            ++out.moved_up;
        else if (p.cpu_delta < -kCpuFlatBandPp)
            ++out.moved_down;
        else
            ++out.moved_flat;

        out.pairs.push_back(std::move(p));
    }

    // candidate-only = candidate machines that never matched a baseline machine.
    for (const MachineVersionScalar& c : candidate)
        if (!baseline_keys.contains(c.agent_id))
            ++out.candidate_only;

    out.paired = static_cast<std::int64_t>(out.pairs.size());
    out.insufficient = (out.paired == 0);
    out.small_cohort = (out.paired > 0 && out.paired < kDexCohortFloor);

    if (out.paired > 0) {
        out.cpu_before_mean = mean(cpu_before);
        out.cpu_after_mean = mean(cpu_after);
        out.cpu_delta_median = scalar_percentile(cpu_delta, 0.5);
        out.cpu_before_p95 = scalar_percentile(cpu_before, 0.95);
        out.cpu_after_p95 = scalar_percentile(cpu_after, 0.95);
        out.ws_before_mean = mean_i64(ws_before);
        out.ws_after_mean = mean_i64(ws_after);
        out.ws_delta_median = scalar_percentile(ws_delta, 0.5);
        out.ws_before_p95 = scalar_percentile(ws_before, 0.95);
        out.ws_after_p95 = scalar_percentile(ws_after, 0.95);
    }

    // Largest CPU mover first — factual ordering for the drill, not a verdict.
    std::sort(out.pairs.begin(), out.pairs.end(),
              [](const MachinePair& a, const MachinePair& b) { return a.cpu_delta > b.cpu_delta; });

    return out;
}

PairedComparison build_comparison(const std::vector<AppPerfCohortRow>& rows,
                                  std::string_view baseline_version,
                                  std::string_view candidate_version, int window_days) {
    return compare(reduce_version_window(rows, baseline_version, window_days),
                   reduce_version_window(rows, candidate_version, window_days), baseline_version,
                   candidate_version, window_days);
}

std::int64_t cohort_no_data(const PairedComparison& c, std::int64_t member_count) {
    const std::int64_t nd = member_count - (c.paired + c.baseline_only + c.candidate_only);
    return nd < 0 ? 0 : nd;
}

} // namespace yuzu::server
