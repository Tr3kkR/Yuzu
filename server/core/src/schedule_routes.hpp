#pragma once

/// @file schedule_routes.hpp
/// `POST /api/schedules` — extracted from the inline server.cpp lambda so the
/// permission-gate ordering has direct unit coverage (PR #1806 adversarial
/// review finding H-01).
///
/// A created schedule fires unattended through `ScheduleRunner::tick()` with
/// NO per-fire permission check — there is no operator session on that
/// background-thread path, so create-time is the only gate. `Schedule:Write`
/// alone must not let a principal reach fleet-wide command dispatch (empty
/// scope_expression == send-to-all, default requires_approval == false ==
/// no approval gate); every other execution-producing route in server.cpp
/// (POST /api/command, the instruction-execute routes) gates
/// `Execution:Execute`, and schedule creation must match.
///
/// CREATE-ONLY (PR1.5a): this file declares and defines exactly one handler.
/// A schedule's `parameters` (schedule_params_parsers.hpp) are set at
/// creation and are immutable thereafter — there is no update route, and
/// none should be added here without a deliberate design pass (parameters
/// feed p8's plan hash, so an in-place mutation path needs its own
/// re-validation and audit story). Changing a schedule's parameters today
/// means delete-and-recreate.

#include <httplib.h>

namespace yuzu::server {

class AuthRoutes;
class ScheduleEngine;

/// Handles `POST /api/schedules`: requires BOTH `Schedule:Write` and
/// `Execution:Execute` (H-01), parses the request body, creates the
/// schedule, and audits the outcome. `schedule_engine` may be null (503).
void handle_create_schedule(AuthRoutes& auth_routes, ScheduleEngine* schedule_engine,
                            const httplib::Request& req, httplib::Response& res);

} // namespace yuzu::server
