- **`/auto` deployment advance now dispatches under the real operator's identity, not system
  authority — and confines to that operator's `Execution:Execute` visibility, not just the
  devices they can see listed.** `DeploymentRoutes::advance_and_render`/`deployment::advance`
  previously fed the shared dispatch chokepoint a `DispatchCaller{.system = true}` closure for
  every deploy-advance tick, so `content_dist.stage`/`content_dist.execute_staged` — declared
  `SoftwareDeployment:Write`/`Execution:Execute` respectively — dispatched unconditionally: the
  chokepoint's classification/authorization check never ran against the triggering operator's own
  grants at all. Both now carry the triggering session's real identity (mirroring the same
  `DispatchCaller`-threading pattern already applied to
  `RestApiV1`/`WorkflowRoutes`/`BundleOrchestrator`/`McpServer`/`DashboardRoutes`), and the
  caller's `Execution:Execute` visible set is populated the same way those five surfaces populate
  it — closing a second gap the caller-threading fix itself introduced: with `exec_visible` left
  unpopulated, the chokepoint's own per-target intersection was a silent no-op, so
  `devices_fn(viewer)`-and-cohort's `Infrastructure:Read`/group-membership-based narrowing was
  standing in for a materially different authorization dimension it was never designed to
  substitute for.

  **Operator impact:** `content_dist.execute_staged` (the actual execute-on-device dispatch) is
  itself classified `Execution:Execute`, so a role holding a GLOBAL `Execution:Execute` grant is
  unaffected. A role holding a management-group-**scoped** `Execution:Execute` grant will now
  correctly be refused execution on a device outside that scope, where it previously succeeded —
  the per-device confinement this fix restores was silently a no-op before it. See the upgrade
  note in `docs/user-manual/server-admin.md` for who this affects and what to check before
  upgrading.
