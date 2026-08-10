- **`docs/user-manual/audit-log.md`'s Logged Actions table now documents the
  `mcp.session.*` verb family.** The table presents itself as the exhaustive
  catalogue ("The following actions are recorded automatically"), but had zero
  rows for `mcp.session.open` / `mcp.session.close` / `mcp.session.reject`
  (`target_type=McpSession`) — the audit emission itself is not new and isn't
  changed by this PR. The new row covers the `target_id`/`detail` shape for
  each verb (including that `mcp.session.close`'s `result=success` describes
  the close itself succeeding, not the triggering request — a replay-window
  force-termination still answers `404` to the client), the full set of
  `mcp.session.reject` causes across `initialize`/`GET`/`DELETE`/streamed-POST,
  and a pointer to `docs/observability-conventions.md` for the closed `reason=`
  enumeration rather than restating it (#2917).
