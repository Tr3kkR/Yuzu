- **`GET /api/v1/network/fleet` and the MCP `get_network_fleet` tool now return `available_keys`**,
  the fleet's tag keys for the cohort-picker UI — previously only the `/network` dashboard fragment
  had this, so an API/agentic caller could not populate the same cohort picker the dashboard shows.
  Closes that dashboard/API parity gap. (DEX exposes the equivalent via its dedicated
  `GET /api/v1/dex/perf/cohorts` route; network has no cohorts route, so the distinct tag keys are
  surfaced on the fleet resource itself, bounded by the 5s network snapshot cache.)
