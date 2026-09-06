- **REST + MCP twin recipe.** `docs/api-twin-recipe.md` documents the pattern the ~36-PR
  api-parity programme (#2146) follows to add a REST v1 route + MCP tool twin for an existing
  dashboard-only capability: the shared-builder rule that keeps REST/MCP JSON shapes from drifting,
  the REST and MCP registration checklists, the per-surface audit fail-mode table (REST fails
  closed, dashboard fragments proceed, MCP flags `audit_persisted:false`), the dispatch/list
  chokepoints, the test recipe, and a full worked example.
