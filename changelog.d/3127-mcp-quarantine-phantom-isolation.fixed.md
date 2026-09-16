- **MCP `quarantine_device` no longer reports a device isolated when it wasn't, and its retry
  no longer dead-ends (#3127).** The handler previously returned the success envelope whenever
  the store write succeeded, even when `agents_reached` was 0 — a record persisted with no live
  isolation, reported as a clean success. It has separately dead-ended a legitimate retry: a
  second call against an already-quarantined device returned a terminal `400 already quarantined`
  instead of re-driving dispatch, so a caller whose first attempt found the agent offline had no
  way back in. Both are fixed together: a write outcome of "record already active" now proceeds
  to dispatch instead of erroring, re-dispatching the *stored* reason/whitelist (never the retry
  call's own, unpersisted values — a differing whitelist on the retry is reported back as
  `whitelist_request_ignored` rather than silently applied), and the response only claims success
  (`dispatch_confirmed: true`) when the isolation dispatch was actually accepted by at least one
  agent and didn't throw; otherwise it returns a retryable error instead of a phantom success.
  Callers built against the old contract will see previously-successful `agents_reached=0` calls
  become retryable errors — a deliberate response-shape break, not a regression.
  Three MCP integration tests that pinned the superseded contract were rewritten to match:
  the records-only (`agents_reached=0`) case now expects a retryable error instead of a
  success envelope, the per-device scope-gate case now wires a dispatch stub so it still
  reaches a result envelope, and the already-quarantined business-error case now asserts
  the stored-intent retry re-dispatch instead of a terminal `400`.
