- **Breaking — operator policy remediation is now arbitrated by a durable per-(policy,agent) claim (HA WS-3 3.4).**
  `PolicyEvaluator::remediate()` claims each target in `PolicyStore` before dispatching the fix, closing a
  double-dispatch / double-attempt-count hazard under active-active HA where two replicas could
  independently remediate the same agent. A `remediate()` call for a target that is already claimed for
  remediation or has already exhausted its fix-retry cap is now **refused at claim time** (HTTP 409,
  `"remediation already in flight or retry cap reached for this policy"`) rather than dispatching the fix a
  wasted extra time and only then recording the failure as the target's status. The `202` response's
  `agents` field now reports the **delivered** count — targets the fix was actually dispatched to — not the
  attempted count; a claimed-but-undelivered target (offline / quarantined / plugin absent) is excluded.
  Automation asserting `agents == len(agent_ids)` should be updated.
