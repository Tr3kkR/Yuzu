- **PG pool exhaustion no longer cascades into httplib worker-pool exhaustion.**
  `PgPool::try_acquire_for`/`with_txn_for` now fail fast once the shared connection pool is
  already saturated at the moment of acquire (a bounded ~500ms ceiling, `Options::
  saturated_fast_fail`), instead of blocking the calling httplib worker for the caller's full
  timeout (previously up to 1500ms-4000ms depending on the store). Under sustained PG
  saturation this frees worker threads for unrelated routes, including auth, instead of pinning
  them on a connection unlikely to free up in time. Closes governance finding
  `up-2146-a2r1-httplib-worker-cascade`, raised against the execution-history read paths this
  branch added (`get_execution_checked`, `get_children_checked`), and applies automatically to
  every other store sharing the pool.
