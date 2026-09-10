- **`GET /api/v1/network/fleet` and the MCP `get_network_fleet` tool now return `available_keys`**,
  the fleet's tag keys for the cohort-picker UI — previously only the `/network` dashboard fragment
  had this, so an API/agentic caller could not populate the same cohort picker the dashboard shows.
  Closes that dashboard/API parity gap (mirrors the existing DEX `available_keys` precedent).
