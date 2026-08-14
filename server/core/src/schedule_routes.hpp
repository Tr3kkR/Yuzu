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
/// stays reachable as the kill switch, H-01), `DELETE /api/schedules/{id}`,
/// and `GET /api/schedules` (list). A created/enabled schedule fires
/// unattended through `ScheduleRunner` with NO per-fire confinement
/// (`exec_visible=std::nullopt`, background engines dispatch as SYSTEM) —
/// worse than a one-shot mutating read, since a service token sharing its
/// creating principal's username (`ApiToken::principal_id`) could otherwise
/// arm recurring fleet-wide dispatch or destroy another principal's
/// schedule. `DELETE` bundles in as the same owner-scoping class
/// (`delete_schedule(id, user)`/`set_enabled(id, enabled, user)` are username-
/// scoped, and a service token shares its creator's username). `GET` (list)
/// is a separate, worse-than-username-scoping gap found in a hardening
/// sweep: `ITServiceOwner` grants full CRUD on `Schedule` and
/// `ScheduleEngine::query_schedules` has no owner/service filter of any
/// kind, so a bare `Schedule:Read` gate lets a service-scoped token
/// enumerate every schedule from every other service — blanket-denied here
/// since there is no single schedule to confine per-target against. Proper
/// fix (persist the minting token's scope on the schedule row, derive
/// `ScheduleRunner`'s `exec_visible` from it, and confine the list read to
/// it) is dedicated follow-up work.
///
/// Returns true iff the caller must return immediately: the 403 was written.
/// Call this AFTER the route's own permission gate(s) succeed, so the session
/// `resolve_session` re-reads is known to exist — this helper does not write
/// a response on a missing/invalid session, only on an affirmative deny.
bool deny_service_scoped_schedule(AuthRoutes& auth_routes, const httplib::Request& req,
                                  httplib::Response& res, const std::string& action,
                                  const std::string& audit_detail);

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
