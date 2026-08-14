- **`/auto` deployment advance now dispatches under the real operator's identity, not system
  authority — and confines to that operator's `Execution:Execute` visibility, not just the
  devices they can see listed.** `DeploymentRoutes::advance_and_render`/`deployment::advance`
  previously fed the shared dispatch chokepoint a `DispatchCaller{.system = true}` closure for
  every deploy-advance tick, so `content_dist.stage`/`content_dist.execute_staged` — declared
  `SoftwareDeployment:Write` — dispatched unconditionally: a role holding
  `SoftwareDeployment:Execute` but not `Write` was never actually checked at all. Both now carry
  the triggering session's real identity (mirroring the same `DispatchCaller`-threading pattern
  already applied to `RestApiV1`/`WorkflowRoutes`/`BundleOrchestrator`/`McpServer`/`DashboardRoutes`),
  and the caller's `Execution:Execute` visible set is populated the same way those five surfaces
  populate it — closing a second gap the caller-threading fix itself introduced: with
  `exec_visible` left unpopulated, the chokepoint's own per-target intersection was a silent
  no-op, so `devices_fn(viewer)∩cohort`'s `Infrastructure:Read`/group-membership-based cohort
  narrowing was standing in for a materially different authorization dimension it was never
  designed to substitute for. Operator impact: a role granted `SoftwareDeployment:Write` +
  `Execute` but scoped away from `Execution:Execute` on some devices will now correctly be
  refused staging/execution on those devices, where it previously succeeded.
