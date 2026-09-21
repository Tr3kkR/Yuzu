- Internal: added the in-process `WorkflowApi` seam for the multi-step-workflow read surface
  (ADR-0031 WS-A4, the eighth per-family seam) — a store-type-free abstract `workflow_api.hpp`
  covering `GET /api/v1/workflows`, `GET /api/v1/workflows/{id}`, and
  `GET /api/v1/workflow-executions/{id}`, plus their MCP twins `list_workflows`/`get_workflow`/
  `get_workflow_execution`, all routed through the same seam calls so their JSON shapes cannot
  drift, a core-only `make_local_workflow_api` factory, and a `LocalWorkflowApi` implementation
  wrapping `WorkflowEngine::list_workflows`/`get_workflow`/`get_execution` unmodified. `Workflow`/
  `WorkflowStep`/`WorkflowExecution`/`WorkflowStepResult`/`WorkflowQuery` relocated out of
  `workflow_engine.hpp` into a pure `workflow_types.hpp`; `workflow_model.hpp` now depends only on
  that pure header instead of the store-coupled `workflow_engine.hpp`. The legacy unversioned
  `GET`/`POST`/`DELETE`/`.../execute` routes (`workflow_routes.cpp`) are a separate, deliberately
  untouched capability with no public REST v1/MCP twin of their own — unaffected, byte-identical
  behaviour throughout.
