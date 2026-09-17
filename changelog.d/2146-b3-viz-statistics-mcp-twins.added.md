- **MCP twins for fleet visualization and execution/fleet statistics.** `get_fleet_topology` and
  `get_host_topology` bring `GET /api/v1/viz/fleet/topology` and `GET /api/v1/viz/host/{id}/topology`
  to MCP parity — the 3D fleet visualizer's first MCP presence — sharing the offline-host merge rule
  (`merge_offline_topology`) and the M-1 `machines_max` DoS cap with the REST route. `get_execution_statistics`,
  `get_execution_statistics_by_agent`, `get_execution_statistics_by_definition`, and `get_fleet_statistics`
  bring `GET /api/v1/execution-statistics{,/agents,/definitions}` and `GET /api/v1/statistics` to MCP
  parity, sharing their JSON-building functions (`execution_statistics_model.hpp`) with the REST routes
  so the two surfaces cannot drift (api-parity programme, #2146 Batch B3).
