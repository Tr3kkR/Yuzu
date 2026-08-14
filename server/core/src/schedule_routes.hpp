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

#include <string>

namespace yuzu::server {

class AuthRoutes;
class ScheduleEngine;

/// Handles `POST /api/schedules`: requires BOTH `Schedule:Write` and
/// `Execution:Execute` (H-01), parses the request body, creates the
/// schedule, and audits the outcome. `schedule_engine` may be null (503).
void handle_create_schedule(AuthRoutes& auth_routes, ScheduleEngine* schedule_engine,
                            const httplib::Request& req, httplib::Response& res);

/// Interim deny for a service-scoped API token on `POST /api/schedules`
/// (create), `POST /api/schedules/{id}/enable` (enable=true only — disable
/// stays reachable as the kill switch, H-01), and `DELETE /api/schedules/{id}`.
/// A created/enabled schedule fires unattended through `ScheduleRunner` with
/// NO per-fire confinement (`exec_visible=std::nullopt`, background engines
/// dispatch as SYSTEM) — worse than a one-shot mutating read, since a service
/// token sharing its creating principal's username (`ApiToken::principal_id`)
/// could otherwise arm recurring fleet-wide dispatch or destroy another
/// principal's schedule. `DELETE` bundles in as the same owner-scoping class
/// (`delete_schedule(id, user)`/`set_enabled(id, enabled, user)` are username-
/// scoped, and a service token shares its creator's username). Proper fix
/// (persist the minting token's scope on the schedule row, derive
/// `ScheduleRunner`'s `exec_visible` from it) is dedicated follow-up work.
///
/// Returns true iff the caller must return immediately: the 403 was written.
/// Call this AFTER the route's own permission gate(s) succeed, so the session
/// `resolve_session` re-reads is known to exist — this helper does not write
/// a response on a missing/invalid session, only on an affirmative deny.
bool deny_service_scoped_schedule(AuthRoutes& auth_routes, const httplib::Request& req,
                                  httplib::Response& res, const std::string& action,
                                  const std::string& audit_detail);

} // namespace yuzu::server
