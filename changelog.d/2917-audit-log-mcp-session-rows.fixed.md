- **`docs/user-manual/audit-log.md`'s Logged Actions table now documents the
  `mcp.session.*` verb family.** The table presents itself as the exhaustive
  catalogue ("The following actions are recorded automatically"), but had zero
  rows for `mcp.session.open` / `mcp.session.close` / `mcp.session.reject`
  (`target_type=McpSession`). The new row covers the `target_id`/`detail`
  shape for each verb (including that `mcp.session.close`'s `result=success`
  describes the close itself succeeding, not the triggering request — a
  replay-window force-termination still answers `404` to the client), the
  distinct `initialize`-time vs. `GET`-time concurrency-cap reason vocabularies
  (`per_principal_cap`/`global_cap`/`id_generation` vs.
  `per_principal_stream_cap`/`global_stream_cap` — easy to conflate given the
  similar names, they come from two different subsystems), and a pointer to
  `docs/observability-conventions.md` for the closed `reason=` enumeration
  rather than restating it. Two `id_generation`/`terminal_poisoned` reasons
  missing from that enumeration were added there in the same PR so the pointer
  is actually accurate (#2917).
