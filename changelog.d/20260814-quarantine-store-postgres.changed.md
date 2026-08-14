- **`QuarantineStore` (Guardian device-quarantine bookkeeping) migrated from SQLite to
  PostgreSQL** (schema `quarantine_store`, ADR-0047), with a mandatory first-boot backfill of
  the legacy `quarantine.db` — an active quarantine record is live security containment
  state, not expendable telemetry, so losing it on cutover would silently un-quarantine a
  device in the server's view. `GET /api/v1/quarantine`, `POST /api/v1/quarantine`, `DELETE
  /api/v1/quarantine/{agent_id}`, and the MCP `quarantine_device` tool now return **HTTP
  503** / JSON-RPC `-32603` (internal error) on a genuine database outage instead of
  collapsing every failure to `400`/JSON-RPC `-32602` (invalid params) — an operator or
  automation client can now tell "the database is unavailable, retry" apart from "that
  request was invalid" (e.g. the device is already quarantined). "At most one active
  quarantine record per agent" is now enforced by a database-level partial unique index
  rather than an in-process mutex, so `quarantine_device`/`release_device` are race-safe
  under real concurrent connections. Operator note: a corrupt local `quarantine.db`, an
  unrecognised legacy status value, or more than 500,000 legacy records now fails the WHOLE
  server's boot (previously silently disabled only the quarantine feature) — this should only
  ever surface as a startup log line naming the exact reason and a repair-or-move-aside
  remediation. On a multi-replica deployment, if two replicas' legacy files hold genuinely
  different content, the backfill refuses with a "HOLDER-SIDE VERIFICATION FAILED" log line
  rather than silently accepting whichever replica happened to migrate first — see
  `docs/user-manual/upgrading.md` for the full list of refusal modes and remediation.
