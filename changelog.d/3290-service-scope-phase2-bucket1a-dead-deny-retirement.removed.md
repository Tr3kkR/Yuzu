- **Retired five provably-dead after-gate service-scope denies (#3290 Phase 2 bucket 1a).**
  `AuthRoutes::deny_service_scoped_schedule` (`schedule_routes.{hpp,cpp}`) is removed
  entirely — all four of its call sites (`POST /api/schedules` create, `GET /api/schedules`
  list, `DELETE /api/schedules/{id}`, `POST /api/schedules/{id}/enable`) fired after their
  route's own `require_permission` gate, which guardian-confinement-2298 PR 3 ("the flip")
  already made unreachable for a service-scoped token. MCP `get_dex_group_app_perf`'s
  interim `deny_fleet_wide_service_scoped()` call is retired the same way. No observable
  behavior change: a service-scoped token still receives the same `403` on every affected
  route, now produced by `require_permission`/`perm_fn` directly instead of the retired
  helpers.
