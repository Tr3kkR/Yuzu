- **REST + MCP read twins for the `/auto` pre-flight & deploy stages.** `GET /api/v1/preflight/runs`
  (MCP `list_preflight_runs`) and `GET /api/v1/deployments/preview` (MCP `get_deployment_preview`)
  bring the pre-flight ASSESS stage's saved-runs rail and the deploy ACT stage's go/warn preview to
  REST + MCP parity — the first API surface either domain has ever had (api-parity programme, #2146
  Batch A). Both are owner-scoped, read-only, and share their JSON-building functions
  (`preflight_run_row_json` / `deploy_preview_json`) with the underlying HTMX fragments so the three
  surfaces cannot drift from each other.
