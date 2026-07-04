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
