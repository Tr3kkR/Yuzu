#pragma once

/// @file test_verify_api_double.hpp
/// FnVerifyApi — a test-only `VerifyApi` adapter wrapping the pre-ADR-0031-
/// WS-A4 `AppPerfCohortFn`-shaped provider (`CohortRead(group_id, app,
/// baseline, candidate, window_days)`), the shape every existing VERIFY-
/// compare test harness already builds. Performs the SAME assembly
/// `LocalVerifyApi::compare` does (verify_api.cpp) — canonicalize both
/// versions, then `build_comparison` — so a test fixture only needs to supply
/// raw `CohortRead` rows, exactly as it did before this seam existed.
///
/// NOT for production use — the production factory is `make_local_verify_api`
/// (verify_api_local.hpp).

#include "app_perf_compare.hpp"    // build_comparison, PairedComparison
#include "dex_app_perf_model.hpp" // AppPerfCohortFn, CohortRead
#include "verify_api.hpp"

#include <yuzu/version_string.hpp> // canon_version

#include <functional>
#include <optional>
#include <string>
#include <utility>

namespace yuzu::server::test {

class FnVerifyApi final : public yuzu::server::VerifyApi {
public:
    using Fn = yuzu::server::AppPerfCohortFn;

    explicit FnVerifyApi(Fn fn) : fn_(std::move(fn)) {}

    [[nodiscard]] std::optional<yuzu::server::VerifyCompareResult>
    compare(const yuzu::server::VerifyCompareQuery& q) const override {
        if (!fn_)
            return std::nullopt;
        auto cohort =
            fn_(q.group_id, q.app, q.baseline_version, q.candidate_version, q.window_days);
        if (!cohort)
            return std::nullopt;
        yuzu::server::VerifyCompareResult out;
        out.member_count = cohort->member_count;
        out.truncated = cohort->truncated;
        const std::string base = yuzu::util::canon_version(q.baseline_version);
        const std::string cand = yuzu::util::canon_version(q.candidate_version);
        out.comparison = yuzu::server::build_comparison(cohort->rows, base, cand, q.window_days);
        return out;
    }

private:
    Fn fn_;
};

} // namespace yuzu::server::test
