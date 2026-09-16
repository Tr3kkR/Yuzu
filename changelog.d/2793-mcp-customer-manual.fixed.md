- **MCP customer-manual gaps closed ahead of the streamed-POST default flip (#2793).**
  `docs/user-manual/mcp.md`'s `-32007` entry ("Unknown or expired session") now covers a
  session-termination cause: a `GET` resume whose cursor has aged out of the replay ring
  terminates the session server-side (`reason=replay_window_exceeded`) rather than
  answering with a gap. This is ordinary ring eviction, reachable today independent of
  streamed POST — the streamed-POST admission reclaim (#2740) adds a second, faster way to
  reach it, when a session's repeated client disconnects release an undelivered final's
  eviction exemption. The `-32012` entry ("Stream limit reached") now covers all four
  streamed-POST causes with client-actionable remediation, alongside the two pre-existing
  GET-channel causes: the shared cross-surface stream budget, this principal's own fixed
  streamed-POST allowance (not governed by `--mcp-max-streams-per-principal`, which is
  GET-only), a server-wide progress-record capacity ceiling, and this session's own
  reclaim-found-nothing state. Both entries cite `docs/mcp-server.md`'s reclaim mechanism
  rather than restating it.
