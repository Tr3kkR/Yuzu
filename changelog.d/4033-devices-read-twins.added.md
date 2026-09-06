- **Devices REST/MCP read twins (#2146 API-parity Batch A).** `GET /api/v1/devices`
  (fleet list) and `GET /api/v1/devices/{id}` (detail) bring the `/devices`
  dashboard's device-identity read to REST parity, migrated onto
  `AuthRoutes::require_fleet_read` — the canonical admit-then-filter chokepoint —
  rather than the fragment's bespoke per-operator scoping, so a management-group-
  confined operator and a correctly-confined service-scoped token both get a real,
  filtered read instead of an outright fleet view or denial. Both routes share a new
  pure JSON builder (`device_agent_row_json`/`device_agent_detail_json`,
  `device_routes.hpp`) so REST and the pre-existing MCP `list_agents`/
  `get_agent_details` tools serve the same row/detail shape. The create-group
  agent-count preview (`/fragments/create-group-form`) also gains a REST twin,
  `GET /api/v1/management-groups/agent-count-preview`, and an MCP twin,
  `preview_management_group_agent_count`, sharing one builder
  (`group_agent_count_preview.hpp`) across all three surfaces. Migrating MCP
  `list_agents` onto the same fleet-read chokepoint is tracked separately as #4041
  (its current unconfined-fan-out gap is a distinct, already-filed P1 bug, not
  silently carried by this change).
