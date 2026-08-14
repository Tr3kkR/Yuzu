- **`docs/user-manual/rest-api.md`'s `POST /mcp/v1/` section now documents progress
  tracking and streamed responses.** Previously it described only the plain JSON-RPC
  request/response shape, with no mention of `_meta.progressToken`, the SSE-capable
  `Accept` header that turns the same POST into a held-open streamed response (2f PR
  3b, `--mcp-enable-streamed-post`), or the streamed-POST `-32012`/429 capacity-denial
  causes — an integrator reading only the REST reference had no way to discover this
  endpoint's most consequential behavior change. The new section covers how to opt in
  (including that a present-but-invalid `Mcp-Session-Id` fails the whole call, not just
  progress tracking), the response headers and shape, and points to
  `docs/user-manual/mcp.md`'s `-32012` troubleshooting entry for the cause-by-cause
  remediation and `docs/mcp-server.md`'s "Streamed POST" section for the admission
  table and wire-level detail, rather than restating either. Also corrects an adjacent,
  pre-existing stale line in the `GET /mcp/v1/` section that still said progress
  delivery "arrives with the next 2f rung" — that rung already shipped (#2916).
