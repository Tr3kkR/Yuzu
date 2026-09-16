- Agent: **Lands dormant — no deployment setting to review.** Guardian does not route
  detection through Spark in any shipped build, so this change ships no user-facing
  behavior today. Spark's drift-detection debounce window no longer inherits the legacy
  detection path's flat 1000ms default. Legacy's default suits its notification-driven
  model, which never re-evaluates a rule on its own; Spark's convergence scheduler does,
  sweeping every armed rule on a fixed per-type cadence (60s for service/registry rules,
  600s for file rules), so the 1000ms window expired before every single sweep and a
  persistently-drifted rule re-emitted its drift event on every sweep of its lane. The
  default is now computed from each rule's own lane cadence plus a jitter margin instead,
  roughly halving that steady-state rate as an interim measure (a fuller redesign remains
  open for later, #3388). Legacy's own default is unaffected — it still gets the same
  1000ms it always has. `prefer_spark` is a compile-time default that cannot be changed
  without a rebuild, so the currently-shipping detection path is unaffected.
