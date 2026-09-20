#pragma once

/// @file test_dex_perf_api_double.hpp
/// FnDexPerfApi — a test-only `DexPerfApi` adapter wrapping the pre-seam
/// `DexPerfFn` (heartbeat-now) + `AppPerfProviders` (app-perf-over-time)
/// shapes every existing DEX-perf REST/MCP test harness already builds.
/// Performs the SAME assembly `LocalDexPerfApi` does (dex_perf_api.cpp) —
/// apply `app_perf_fleet_trend`/`app_perf_group_trend` + `kDexCohortFloor`,
/// serialize the device drill via `dex_device_app_perf_json` — so a test
/// fixture only needs to supply the SAME raw-row lambdas it did before this
/// seam existed. Mirrors `FnVerifyApi` (test_verify_api_double.hpp), the
/// established pattern for this exact "wire the real seam over a
/// function-shaped test double" problem.
///
/// NOT for production use — the production factory is `make_local_dex_perf_api`
/// (dex_perf_api_local.hpp), which wires real store pointers instead.

#include "dex_app_perf_builders.hpp" // app_perf_fleet_trend/group_trend, dex_device_app_perf_json, AppPerfProviders
#include "dex_perf_api.hpp"
#include "dex_perf_model.hpp" // DexPerfFn

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::test {

class FnDexPerfApi final : public yuzu::server::DexPerfApi {
public:
    FnDexPerfApi(yuzu::server::DexPerfFn dex_perf_fn, yuzu::server::AppPerfProviders providers)
        : dex_perf_fn_(std::move(dex_perf_fn)), providers_(std::move(providers)) {}

    [[nodiscard]] yuzu::server::DexPerfSnapshot
    fleet_snapshot(const std::string& cohort_key) const override {
        return dex_perf_fn_ ? dex_perf_fn_(cohort_key) : yuzu::server::DexPerfSnapshot{};
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfAppSummary>>
    apps(bool& truncated) const override {
        if (!providers_.apps)
            return std::nullopt;
        return providers_.apps(truncated);
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfTrendPoint>>
    app_fleet_trend(const std::string& app, const std::string& version) const override {
        if (!providers_.fleet)
            return std::nullopt;
        auto rows = providers_.fleet(app, version);
        if (!rows)
            return std::nullopt;
        return yuzu::server::app_perf_fleet_trend(*rows);
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfVersionDeviceRow>>
    app_version_devices(const std::string& app, const std::string& version,
                        const std::optional<std::vector<std::string>>& visible_agent_ids,
                        bool& truncated) const override {
        if (!providers_.version_devices)
            return std::nullopt;
        return providers_.version_devices(app, version, visible_agent_ids, truncated);
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfTrendPoint>>
    group_trend(const std::string& group_id, const std::string& app,
               const std::string& version) const override {
        if (!providers_.group)
            return std::nullopt;
        auto rows = providers_.group(group_id, app, version);
        if (!rows)
            return std::nullopt;
        return yuzu::server::app_perf_group_trend(*rows, yuzu::server::kDexCohortFloor);
    }

    [[nodiscard]] std::optional<std::vector<yuzu::server::AppPerfTrendPoint>>
    tag_trend(const std::string& tag_key, const std::string& tag_value, const std::string& app,
             const std::string& version) const override {
        if (!providers_.tag_cohort)
            return std::nullopt;
        auto rows = providers_.tag_cohort(tag_key, tag_value, app, version);
        if (!rows)
            return std::nullopt;
        return yuzu::server::app_perf_group_trend(*rows, yuzu::server::kDexCohortFloor);
    }

    [[nodiscard]] std::optional<std::string>
    device_app_perf_json(const std::string& agent_id, const std::string& app_filter,
                         bool audit_persisted) const override {
        if (!providers_.device)
            return std::nullopt;
        auto rows = providers_.device(agent_id);
        if (!rows)
            return std::nullopt;
        return yuzu::server::dex_device_app_perf_json(agent_id, app_filter, *rows,
                                                       audit_persisted);
    }

private:
    yuzu::server::DexPerfFn dex_perf_fn_;
    yuzu::server::AppPerfProviders providers_;
};

} // namespace yuzu::server::test
