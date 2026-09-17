- **`/devices` dashboard list search no longer matches on device tags.** Searching the fleet device
  list now matches hostname/agent ID/OS/architecture only — the device *detail* page (`/device?id=`)
  still shows and is unaffected. This is a side effect of routing the list through the new in-process
  `DeviceApi` seam (ADR-0031 WS-A4), which has no bulk all-agents tag read (`TagStore` is per-agent);
  a minor, honest functional narrowing rather than a regression anyone tested against.
- **`GET /api/v1/devices/{id}` and the MCP `get_agent_details` tool now always return a `tags` array**
  (as `[]` when the device has none), where previously the key was omitted in the case of an unwired
  `TagStore` — a configuration that never occurs in production (TagStore is a core Postgres store and
  the server fails closed without it). Callers relying on `tags`' presence to detect that case should
  check for an empty array instead.
