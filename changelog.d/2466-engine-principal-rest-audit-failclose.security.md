- The REST engine-principal routes (`/api/v1/engine-principals` create, revoke,
  transfer-owner, credential mint/rotate/confirm, and role assign/unassign) now
  **fail closed** when their audit row cannot be persisted: the response is
  `503` with a `Sec-Audit-Failed: true` header rather than a success that leaves
  a privileged mutation unrecorded (ADR-1005 "mutations fail closed on audit
  failure"). The credential mint/rotate routes withhold the one-time secret on
  such a failure — for a rotate, re-rotate within the overlap window to re-serve
  the same audited successor secret; for a mint, rotate the orphaned credential
  to obtain an audited secret. Reads (list,
  get, the no-admin auditor, GET roles) and the engine-session denial belt now
  set the same header while still proceeding, matching the MCP twins'
  `audit_persisted:false` semantics. Closes #2466 and #2406.
