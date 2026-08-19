#include "schedule_routes.hpp"

#include "auth_routes.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_denial (deny_service_scoped_schedule)
#include "schedule_engine.hpp"
#include "schedule_params_parsers.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace yuzu::server {

bool deny_service_scoped_schedule(AuthRoutes& auth_routes, const httplib::Request& req,
                                  httplib::Response& res, const std::string& action,
                                  const std::string& audit_detail, const std::string& permission) {
    auto session = auth_routes.resolve_session(req);
    if (!session || session->token_scope_service.empty())
        return false;
    // Write the 403 FIRST, audit after (mirrors PreflightRoutes/DeploymentRoutes'
    // deny_service_scoped_): a throwing audit_log must not suppress the 403.
    // `permission` defaults empty (see header) — a caller passing a non-empty
    // override is now itself a bug, since no grant admits a service-scoped
    // caller here. `a4_denial` also mints/reuses the X-Correlation-Id header
    // (this call site used to set it unconditionally via `res.set_header`,
    // which `emplace`s into httplib's header multimap rather than replacing
    // in place — an upstream-minted cid wasn't overwritten so much as joined
    // by a second entry, leaving which value the caller actually saw
    // dependent on header-serialization order. Now reused instead — #3167).
    res.status = 403;
    res.set_content(
        detail::a4_denial(
            res, 403, "service-scoped tokens may not access this fleet-wide schedule surface",
            detail::A4ErrorOpts{.permission = permission}),
        "application/json");
    // target_type "schedule" (lowercase) matches every existing schedule.*
    // success-path audit row in this file and server.cpp — a capitalized
    // "Schedule" would split the SIEM verb's target_type between rows.
    // Governance finding (cpp-expert): this call was previously uncaught
    // despite the comment above claiming parity with the try/catch-wrapped
    // PreflightRoutes/DeploymentRoutes siblings — a throwing audit_log
    // (bad_alloc-class) would overwrite the already-written 403 body with
    // httplib's default empty 500 (no server-wide exception handler exists,
    // rest_api_v1.cpp:8399). Now genuinely wrapped, matching those siblings.
    try {
        (void)auth_routes.audit_log(req, action, "denied", "schedule", "", audit_detail);
    } catch (const std::exception& e) {
        spdlog::warn("{}: audit_log threw: {}", action, e.what());
    } catch (...) {
        spdlog::warn("{}: audit_log threw (non-std)", action);
    }
    return true;
}

void handle_create_schedule(AuthRoutes& auth_routes, ScheduleEngine* schedule_engine,
                            const httplib::Request& req, httplib::Response& res) {
    if (!auth_routes.require_permission(req, res, "Schedule", "Write"))
        return;
    // H-01: Schedule:Write alone must not reach fleet-wide command dispatch —
    // see the file header. Every execution-producing route gates
    // Execution:Execute; schedule creation must too.
    if (!auth_routes.require_permission(req, res, "Execution", "Execute"))
        return;
    // Interim deny (see schedule_routes.hpp): a service-scoped token passes
    // both gates above via the ITServiceOwner role, which carries neither
    // gate's confinement, so it must be stopped before it can arm a
    // recurring, unconfined-dispatch schedule.
    if (deny_service_scoped_schedule(auth_routes, req, res, "schedule.create", ""))
        return;
    if (!schedule_engine) {
        res.status = 503;
        res.set_content(
            R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
            "application/json");
        return;
    }

    try {
        auto j = nlohmann::json::parse(req.body);
        InstructionSchedule sched;
        sched.name = j.value("name", "");
        sched.definition_id = j.value("definition_id", "");
        sched.frequency_type = j.value("frequency_type", "once");
        sched.interval_minutes = j.value("interval_minutes", 60);
        sched.time_of_day = j.value("time_of_day", "00:00");
        sched.day_of_week = j.value("day_of_week", 0);
        sched.day_of_month = j.value("day_of_month", 1);
        sched.scope_expression = j.value("scope_expression", "");
        sched.requires_approval = j.value("requires_approval", false);

        // Typed schedule parameters (PR1.5a). `parameters` is OPTIONAL — an
        // omitted field dumps to the empty string, which the validator
        // treats identically to an explicit "{}". Validating here (rather
        // than deferring entirely to create_schedule's backstop) gives the
        // caller a specific, typed 400 instead of a generic insert failure.
        std::string params_raw;
        if (j.contains("parameters"))
            params_raw = j["parameters"].dump();
        auto canon_params = validate_and_canonicalize_schedule_params(params_raw);
        if (!canon_params) {
            res.status = 400;
            res.set_content(
                nlohmann::json({{"error", std::string(to_string(canon_params.error()))}}).dump(),
                "application/json");
            return;
        }
        sched.parameter_values = *canon_params;

        if (auto session = auth_routes.resolve_session(req))
            sched.created_by = session->username;

        auto result = schedule_engine->create_schedule(sched);
        if (!result) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                            "application/json");
            return;
        }
        (void)auth_routes.audit_log(req, "schedule.create", "success", "schedule", *result,
                                    sched.name);
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Schedule created","level":"success"}})");
        res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
    } catch (const std::exception& e) {
        res.status = 400;
        res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
    }
}

bool parse_schedule_enabled(const std::string& body) {
    try {
        auto j = nlohmann::json::parse(body);
        if (j.contains("enabled")) {
            if (j["enabled"].is_boolean())
                return j["enabled"].get<bool>();
            if (j["enabled"].is_string())
                return j["enabled"].get<std::string>() != "false";
        }
    } catch (...) {
    }
    return true; // missing key / malformed body — pre-existing default
}

} // namespace yuzu::server
