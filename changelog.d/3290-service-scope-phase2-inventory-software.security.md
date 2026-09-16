- **`GET /api/v1/inventory/software` and MCP `query_installed_software` gain real
  per-request confinement (#3290 Phase 2).** Both migrate onto `AuthRoutes::require_fleet_read`
  as their sole authorization gate, replacing the blanket service-scope deny #2298 PR 3 shipped
  as an interim default: a correctly-confined service-scoped API token now gets a real result
  filtered to its service-tagged agents instead of a 403, and a management-group-confined
  operator (no global grant) now gets a genuinely filtered result instead of an unfiltered one.
  `require_fleet_read` itself gains the elevated/engine/`mcp_tier` caller-class handling it was
  missing since its Phase 0 introduction — closing a real regression the bare primitive would
  otherwise have shipped (an engine principal under RBAC-off falling through to an unfiltered
  fleet-wide read). It also now fails closed (503, retryable) rather than 403 (indistinguishable
  from "no grant") when the management-group store is null or not yet open, matching the
  existing hardening already in place for the RBAC and tag stores.
