- **`docs/user-manual/rest-api.md`'s `POST /mcp/v1/` section now documents progress
  tracking and streamed responses.** Previously it described only the plain JSON-RPC
  request/response shape, with no mention of `_meta.progressToken`, the SSE-capable
  `Accept` header that turns the same POST into a held-open streamed response (2f PR
  3b, `--mcp-enable-streamed-post`), or the streamed-POST `-32012`/429 admission
  causes — an integrator reading only the REST reference had no way to discover this
  endpoint's most consequential behavior change. The new section covers how to opt in,
  the session precondition, the response headers and shape, and points to
  `docs/user-manual/mcp.md`'s `-32012` troubleshooting entry and `docs/mcp-server.md`'s
  "Streamed POST" section for the full cause-by-cause remediation and wire-level detail
  rather than restating either (#2916).
