- **MCP streamed-POST pin-displacement runbook fixes.** `docs/ops-runbooks/mcp-stream-pin-displacement.md`'s
  drift-investigation capture step no longer pulls the benign
  `mcp.bridge.pin_displaced_for_admission` audit rows into an unrelated accounting-drift
  page. The `YuzuMcpStreamedPinSlotsWedged` section now names the actual audit action
  (`mcp.session.reject`) and query for finding an affected session id, instead of a vague
  reference to "the audit rows" that named no queryable event. A new section documents
  how to identify the principal or session behind a rising (non-alertable)
  `pin_displaced_for_admission` rate via `GET /api/v1/audit`. The `for: 15m` window on
  `YuzuMcpStreamedPinSlotsWedged` now has its derivation recorded and pinned by a
  promtool test: a single isolated rejection can never satisfy `for: 15m` by the rule's
  own mathematical shape, only a sustained rate can.
