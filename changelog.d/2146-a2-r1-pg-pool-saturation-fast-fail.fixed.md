- **PG pool exhaustion is substantially less likely to cascade into httplib worker-pool
  exhaustion (mitigated, not eliminated).** `PgPool::try_acquire_for`/`with_txn_for` now fail
  fast once the shared connection pool is already saturated at the moment of acquire (a bounded
  ~500ms ceiling, `Options::saturated_fast_fail`), instead of blocking the calling worker thread
  for the caller's full timeout (previously up to 10 seconds depending on the store, most
  commonly 1500ms-4000ms). Under sustained PG saturation this frees worker threads for unrelated
  routes, including auth, far sooner than before, instead of pinning them on a connection
  unlikely to free up in time -- but the underlying pool-to-worker sizing ratio this finding
  identified is unchanged, so exhaustion under a sufficiently sustained, high-volume saturation
  event remains possible, just at a substantially higher load threshold. Closes governance
  finding `up-2146-a2r1-httplib-worker-cascade` (re-derived to a non-blocking residual severity
  in Gate 8 round 4 given the magnitude of the mitigation), raised against the execution-history
  read paths this branch added (`get_execution_checked`, `get_children_checked`). Applies
  automatically to every other store sharing the pool, including write paths (RBAC, audit,
  quarantine, session, and others) -- a deliberate, uniform chokepoint-level fix rather than a
  read-only-scoped one.
