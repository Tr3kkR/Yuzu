- **MCP twins for the per-device DEX score and app-perf drills.** `get_dex_device_score`
  (`GET /api/v1/dex/devices/{id}`) and `get_dex_device_app_perf`
  (`GET /api/v1/dex/devices/{id}/app-perf`) close the two MCP-only gaps flagged by the
  api-parity programme (#2146 Batch A) — both REST routes already existed with no MCP
  twin. Both gate on the same ancestor-aware SCOPED `GuaranteedState:Read` gate as their
  REST siblings, emit the same domain-verb audit (`dex.device.view` /
  `dex.device.app_perf.view`), and call the same shared builder function
  (`dex_read_model.hpp`) their REST twin calls, so the two response shapes cannot drift.
