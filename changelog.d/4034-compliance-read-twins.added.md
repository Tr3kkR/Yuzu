- **REST v1 + MCP read twins for compliance/policy data (api-parity #2146 Batch A).**
  `GET /api/v1/compliance`, `GET /api/v1/compliance/{id}`, `GET /api/v1/policies`,
  `GET /api/v1/policies/{id}`, and `GET /api/v1/policy-fragments` bring the legacy
  unversioned `/api/compliance*`/`/api/polic*` reads to REST v1 (A4-enveloped) and MCP
  (`get_policy`, `list_policy_fragments`, `get_policy_agent_statuses` — new;
  `list_policies`/`get_compliance_summary`/`get_fleet_compliance` — pre-existing).
  `GET /api/v1/compliance/{id}`'s per-agent status fan-out is gated by the ADR-0017
  `require_fleet_read` admit-then-filter chokepoint, not a bare permission check: a
  management-group- or service-scope-confined caller now sees a real, filtered answer
  (agents + a summary tallied from exactly that filtered set) instead of an unfiltered
  fleet-wide view. The two `/fragments/compliance/*` dashboard fragments now call the
  same shared builders as the new REST/MCP surface (`compliance_model.hpp`) so all
  three can never drift from each other.
