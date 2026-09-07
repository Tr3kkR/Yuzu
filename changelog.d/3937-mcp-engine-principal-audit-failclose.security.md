- The eight MCP engine-principal mutation tools (`create_engine_principal`,
  `revoke_engine_principal`, `transfer_engine_principal_owner`,
  `mint_engine_credential`, `rotate_engine_credential`, `confirm_engine_rotation`,
  `assign_engine_role`, `unassign_engine_role`) now **fail closed** on an
  audit-persist failure — they return a JSON-RPC `503` error (with
  `audit_persisted:false` in the error data) instead of a success result, so a
  privileged identity/credential mutation never reports success on an unrecorded
  audit row (ADR-1005 "mutations fail closed on audit failure"). This brings the
  MCP twins to parity with the now-fail-closed REST routes (#2466) and the
  in-MCP plugin-config precedent. `mint_engine_credential`/`rotate_engine_credential`
  additionally withhold the one-time secret on that path. The mutation has
  already committed, so the error directs the caller to reconcile via a read
  rather than retry. Resolves #3937.
