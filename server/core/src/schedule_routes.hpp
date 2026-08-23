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

#include <string>

namespace yuzu::server {

class AuthRoutes;
class ScheduleEngine;

/// Handles `POST /api/schedules`: requires BOTH `Schedule:Write` and
/// `Execution:Execute` (H-01), parses the request body, creates the
/// schedule, and audits the outcome. `schedule_engine` may be null (503).
void handle_create_schedule(AuthRoutes& auth_routes, ScheduleEngine* schedule_engine,
                            const httplib::Request& req, httplib::Response& res);

/// Parses the `enabled` field of a `POST /api/schedules/{id}/enable` body.
/// Extracted from the inline server.cpp lambda (guardian-confinement-2298
/// hardening sweep) so the parsing has direct unit coverage — the same
/// rationale as `handle_create_schedule`'s own extraction (H-01). Accepts
/// BOTH a genuine JSON boolean and the legacy string encoding
/// (`"true"`/`"false"`); a missing key or a body that fails to parse
/// defaults to `true`, matching the pre-existing contract (disable is an
/// explicit opt-in, never inferred from absence). A real JSON boolean used
/// to fall through this default silently — `extract_json_string` only
/// matches a JSON *string* value — so `{"enabled": false}`, the encoding
/// every standards-compliant JSON client library produces for a boolean
/// field, computed to `enabled=true`: inverting the request and, worse,
/// defeating the disable-always-reachable kill switch (H-01, #1806) for any
/// such caller.
bool parse_schedule_enabled(const std::string& body);

} // namespace yuzu::server
