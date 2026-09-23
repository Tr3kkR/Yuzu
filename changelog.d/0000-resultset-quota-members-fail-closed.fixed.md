- **Result-set async producers now fail closed on a degraded quota check or a truncated membership/list/lineage read, instead of silently proceeding as if the store were empty (#4306, #4307).**
  `ResultSetStore::count_for_owner` returned `0` on a genuine Postgres failure —
  indistinguishable from a genuinely-empty owner — so a degraded read at the
  PRE-DISPATCH per-owner quota check on the three async result-set producers
  (`from-tar-query`, `from-instruction-result`, `re-eval`) let an over-quota
  owner's dispatch fire for real before the authoritative in-transaction
  recheck (which runs *after* dispatch) ever got a chance to refuse it.
  Separately, `members`/`list_by_owner`/`lineage` returned an empty/truncated
  page on the same class of failure, indistinguishable from a genuine last
  page — including inside the `from-inventory-query` parent-narrowing loop,
  which *materialises* the (silently truncated) member set into a durable
  result set future dispatches target. Both producers, the `GET
  /api/v1/result-sets` family, and their MCP twins now refuse (503 REST /
  `kInternalError` MCP) rather than proceeding on a degraded read. The
  quota pre-check's SQL predicate is also now aligned with the authoritative
  in-transaction recheck's own predicate (expired-but-unswept rows no longer
  spuriously count against the quota), and a post-dispatch store fault while
  persisting a pending result set now maps to `500` rather than `400` — it is
  a server fault after a real command already reached agents, not a client
  error.
