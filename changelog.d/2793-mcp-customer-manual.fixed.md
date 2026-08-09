- **MCP customer-manual gaps closed for the streamed-POST admission reclaim (#2740).**
  `docs/user-manual/mcp.md`'s `-32007` entry ("Unknown or expired session") now names a
  cause the reclaim introduces: repeated client disconnects on one session can release an
  undelivered final's ring-eviction exemption, and if ordinary ring eviction later reaches
  it, a subsequent `GET` resume terminates the session server-side (`reason=
  replay_window_exceeded`) rather than answering with a gap — previously undocumented at
  customer level. The `-32012` entry ("Stream limit reached") now covers the three
  streamed-POST causes (`post_per_principal_cap` / `post_global_cap` / `post_pin_slots`),
  each with client-actionable remediation, alongside the two pre-existing GET-channel
  causes. Both cite `docs/mcp-server.md`'s reclaim mechanism rather than restating it.
