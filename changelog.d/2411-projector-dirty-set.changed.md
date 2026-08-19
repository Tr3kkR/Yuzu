- **The MCP progress bridge's projector now visits only records with pending
  work, instead of rescanning every live record on every wake.** `run_projector`
  previously snapshotted the ENTIRE correlation-record table under `bridge_mu_`
  on every wake and unconditionally called `project_record` on all of them,
  even records with nothing new since their last visit — any one record's bus
  event triggered a full O(records_) rescan plus O(records_) `bridge_mu_`/
  per-record-mutex churn, contending with reserve/subscribe/arm on the request
  path. A shared dirty-key set is now pushed by every wake source (the bus
  listener, arm's flip handoff, park/close/dispatch-failure transitions, the
  pressure sweep) and drained by the projector each cycle: a wake visits only
  the record(s) it actually names, cutting the projector to O(dirty) rescans
  and `bridge_mu_` acquisitions per wake. Degrades safely to the old full-table
  scan on a dirty-set allocation failure or a cycle that threw before
  finishing, so no wake source can be silently starved. No observable behavior
  change — the same records get projected, just without visiting every other
  live record to do it. (#2411)
