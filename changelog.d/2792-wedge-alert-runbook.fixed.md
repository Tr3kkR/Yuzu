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
  own mathematical shape, only a sustained rate can — and the derivation now also names
  its own blind spot, a client retrying slower than the window can wedge without the
  alert ever firing. Both new `/api/v1/audit` query recipes now carry an explicit
  truncation caveat: the route's `total`/`page_size` fields describe what came back, not
  what matched ([#2881](https://github.com/Tr3kkR/Yuzu/issues/2881), filed but not fixed
  by this change). `docs/user-manual/audit-log.md`'s `GET /api/v1/audit` example
  previously showed a `total`/`page_size` shape that does not match the route's real
  behaviour (a `limit=20` request returning `"total": 150, "page_size": 20`, implying
  `total` is a true match count and `page_size` mirrors the request); corrected to the
  real shape and given the same truncation caveat. `docs/user-manual/rest-api.md`'s
  equivalent example was numerically accurate but silent on the same risk — added the
  caveat there too.
