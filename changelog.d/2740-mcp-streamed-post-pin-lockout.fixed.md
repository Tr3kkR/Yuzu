- MCP streamed POST: client disconnects can no longer lock a session out of
  streaming (#2740). A peer that dies before its result is written leaves that
  final pinned with no route left to release it — a GET resume or session death
  both need a channel a POST-only client does not have — and four such calls
  exhausted the session's four streamed slots permanently, answering `429` with
  advice to wait for calls that had already ended. Admission now releases the pin
  of the session's oldest parked, undelivered final and admits the new call,
  counting `yuzu_mcp_bridge_pin_displaced_for_admission_total` and auditing
  `mcp.bridge.pin_displaced_for_admission`. The displaced result is unpinned, not
  erased: it stays in the replay ring until ordinary eviction and remains
  fetchable by `execution_id`. Live calls are never displaced, so the per-session
  concurrency limit is intact by construction - with one bounded exception
  tracked as #2795, where a release that loses a race still admits and can leave
  a session transiently one over. The remaining refusal now distinguishes
  slots held by calls in flight from slots held by results that have not reached
  a client, rather than always claiming calls are in flight.
- MCP streamed POST: orphaned replay-ring pins — a committed final whose owning
  record a teardown erased without unpinning — are reclaimed by admission too
  (#2740). Nothing else could ever release them (the pin-ack sweep and the
  delivered-final path both need a record, and a cursor-less GET resume releases
  nothing), so four of them locked a session out of streamed POST permanently
  even though the session stayed alive. Reclaims are counted
  (`yuzu_mcp_bridge_pin_displaced_for_admission_total`, pre-seeded at boot) and
  audited against the admitting principal
  (`mcp.bridge.pin_displaced_for_admission`).
