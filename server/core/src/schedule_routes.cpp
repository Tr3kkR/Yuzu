#include "schedule_routes.hpp"

#include "auth_routes.hpp"
#include "schedule_engine.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

void handle_create_schedule(AuthRoutes& auth_routes, ScheduleEngine* schedule_engine,
                            const httplib::Request& req, httplib::Response& res) {
    if (!auth_routes.require_permission(req, res, "Schedule", "Write"))
        return;
    // H-01: Schedule:Write alone must not reach fleet-wide command dispatch —
    // see the file header. Every execution-producing route gates
    // Execution:Execute; schedule creation must too.
    if (!auth_routes.require_permission(req, res, "Execution", "Execute"))
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

} // namespace yuzu::server
