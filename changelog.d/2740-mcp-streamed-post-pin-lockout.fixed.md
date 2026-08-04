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
  concurrency limit is unchanged, and the remaining refusal now states which of
  the two states it is in rather than always claiming calls are in flight.
