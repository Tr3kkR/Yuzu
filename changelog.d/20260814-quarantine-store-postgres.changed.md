- **`QuarantineStore` (Guardian device-quarantine bookkeeping) migrated from SQLite to
  PostgreSQL** (schema `quarantine_store`, ADR-0047), with a mandatory first-boot backfill of
  the legacy `quarantine.db` — an active quarantine record is live security containment
  state, not expendable telemetry, so losing it on cutover would silently un-quarantine a
  device in the server's view. `POST /api/v1/quarantine`, `DELETE
  /api/v1/quarantine/{agent_id}`, and the MCP `quarantine_device` tool now return **HTTP
  503** / JSON-RPC `-32603` (internal error) on a genuine database outage instead of
  collapsing every failure to `400`/JSON-RPC `-32602` (invalid params) — an operator or
  automation client can now tell "the database is unavailable, retry" apart from "that
  request was invalid" (e.g. the device is already quarantined). `GET /api/v1/quarantine`
  also gains this 503, but from a different starting point: it previously returned a
  silent, misleadingly-empty `200` on a degraded read (SQLite reads essentially never failed
  short of file corruption, so this was not practically reachable) — it now fails closed
  rather than reporting "nothing quarantined" when the true answer is "could not ask". A
  **second, distinct** `GET` 503 cause also lands with this change: the per-record
  admit-then-filter scope check now fails the whole list closed (rather than silently
  dropping just the affected record) on any anomalous outcome, not only an explicit `403`
  deny — this is NOT covered by `yuzu_server_quarantine_read_degrade_total`; see
  `docs/user-manual/upgrading.md` for how to tell the two 503 causes apart by message.
  "At most one active quarantine record per agent" is now enforced by a database-level
  partial unique index rather than an in-process mutex, so `quarantine_device`/`release_device`
  are race-safe under real concurrent connections. Operator note: a corrupt local
  `quarantine.db`, an unrecognised legacy status value, or more than 5,000 legacy records
  now fails the WHOLE server's boot (previously silently disabled only the quarantine
  feature) — this should only
  ever surface as a startup log line naming the exact reason and a repair-or-move-aside
  remediation. On a multi-replica deployment, if two replicas' legacy files hold genuinely
  different content, the backfill refuses with a "HOLDER-SIDE VERIFICATION FAILED" log line
  rather than silently accepting whichever replica happened to migrate first; the SAME log
  line and refusal also cover a single-replica rollback-then-reupgrade — see
  `docs/user-manual/upgrading.md` and `docs/ops-runbooks/quarantine-store-backfill-recovery.md`
  for the full list of refusal modes and remediation. Store-unavailable, scope-gate-unwired, and
  write-failure quarantine paths — including a store/pool outage discovered before the request
  could even be attributed to a device — now emit a `quarantine.enable`/`quarantine.disable`
  audit row (previously silent); input-validation rejections (missing `agent_id`, oversized
  `reason`/`whitelist`, a malformed whitelist token on MCP, a malformed JSON body on REST) do
  not yet audit on either transport (tracked follow-up). `POST`/`DELETE
  /api/v1/quarantine` (REST) and the MCP `quarantine_device` tool carry `retry_after_ms: 5000` on
  a genuine store-failure `503`/`-32603` (never on the non-retryable `400`/`-32602` business-error
  case) — `GET`'s two 503 causes above do not carry this hint (REST-only; MCP has no quarantine
  list or release tool yet).
