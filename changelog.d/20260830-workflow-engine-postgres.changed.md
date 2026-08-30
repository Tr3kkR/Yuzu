- **`WorkflowEngine` (multi-step instruction orchestration, `/api/workflows*` +
  `/api/workflow-executions/*`) now runs on the PostgreSQL substrate** (schema
  `workflow_engine`) instead of its own `workflows.db` SQLite file. Construction is now
  fail-closed — the server refuses to start if the schema can't be created/opened, instead of
  silently serving a store nothing ever health-checked. No data is carried over from a
  pre-Postgres install (fresh-start-by-default, ADR-0009); workflows must be re-created via
  `POST /api/workflows` after upgrading. `workflow_engine` is now reported by both `/readyz`
  (already was) and `/healthz` (newly). `DELETE /api/workflows/:id` now soft-deletes instead of
  a literal FK-cascade port — a deleted workflow's execution history is retained, never
  destroyed; the REST response shape (`{"deleted": true|false}`) is unchanged. `create_workflow`
  and execution admission gain new transactional atomicity, closing a race where a workflow
  deleted concurrently with `execute()` could otherwise create an execution against it.
  `GET /api/workflows?limit=` now rejects `0` or a negative value with `400` instead of silently
  returning one row. See ADR-0064.
