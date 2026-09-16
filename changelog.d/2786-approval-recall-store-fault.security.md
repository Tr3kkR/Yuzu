- **A store fault at the ticket-lookup step of an MCP approval recall is now reported as a
  retryable store error, not as "does not match this request."** The lookup used `get`, which
  collapses a failed SQLite read into "no row", so a moment of contention read as an ordinary
  mismatch, and the remediation told the caller to submit a fresh request, discarding a live,
  human-approved, one-time capability and asking a second human to approve the same thing on a
  failure a retry may have cleared. This is the same burn class the consume-step guard already
  closed, one step earlier on the same request path, reached first. The two failure sites now
  share one response body: an open store reports a temporary failure with a machine-readable
  `retry_after_ms`; a store that never opened reports a permanent failure with none, since only an
  operator restarting the server can clear it. This closes arm 2 of #2786; arm 1 (the security
  signal a masked foreign-origin refusal loses) and the open-handle-permanent-failure gap are
  closed by a follow-up change in the same release.
