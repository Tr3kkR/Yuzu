#pragma once

/// @file verify_routes.hpp
/// The `/auto` VERIFY stage routes — the cohort-paired before/after app-perf
/// evidence (UAT non-functional). Three fragments on the /auto page:
///   * GET /fragments/auto/verify        — the config form (cohort + app + two
///     versions + window). Chrome; gates Infrastructure:Read like the page.
///   * GET /fragments/auto/verify/run     — the AGGREGATE result (summary +
///     shift cards + distribution). Reads DEX app-perf → GuaranteedState:Read.
///     OPERATIONAL audit `dex.app_perf.compare`, set-and-proceed (the aggregate
///     is unfloored + near-individual at canary scale, so the read is recorded —
///     the works-council accountability that replaces a floor; grilled 2026-06-30).
///   * GET /fragments/auto/verify/drill   — the per-machine pairs (the audited PII
///     surface, opened by a deliberate click). GuaranteedState:Read + audit.
///
/// Product UI: HTMX core attrs only (CSP blocks hx-on); every string escaped at
/// render (verify_ui.cpp). EVIDENTIAL ONLY — no verdict. NO cohort floor (real
/// canaries are 2-3 devices); a sub-floor paired set renders "indicative", never
/// suppressed. The numbers come from the ONE pure engine (build_comparison), so
/// this surface and the REST/MCP twins agree. The dashboard renders honest notes
/// at HTTP 200 on bad input / degrade (the dashboard htmx config drops 4xx/5xx
/// bodies — REST/MCP keep their fail-states; this is the HTML surface).

#include <yuzu/server/auth.hpp>

#include "dex_app_perf_model.hpp" // AppPerfCohortFn
#include "dex_routes.hpp"         // DexRoutes::AuditFn

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

class VerifyRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    /// (id, name) of the management groups offered as the cohort dropdown.
    using GroupsFn = std::function<std::vector<std::pair<std::string, std::string>>()>;
    using AuditFn = DexRoutes::AuditFn;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, GroupsFn groups_fn,
                         AppPerfCohortFn cohort_fn, AuditFn audit_fn);

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    GroupsFn groups_fn_;
    AppPerfCohortFn cohort_fn_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
