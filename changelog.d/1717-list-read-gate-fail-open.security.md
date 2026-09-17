- **Closed a fail-open in the permission gate on a corrupt RBAC store.** `require_permission` and
  `require_scoped_permission` now gate on `rbac_enforcement_in_effect()` rather than the raw
  `is_rbac_enabled()` flag, so a corrupt or load-failed `rbac.db` fails **closed** (403) instead of
  falling through to the legacy Read-allow — which had disclosed the whole fleet's per-agent data to
  any authenticated principal the moment the store failed to load. Behaviour is unchanged for fresh
  installs (RBAC not yet enabled) and for deployments with no RBAC store wired. (ADR-0017 ship-now fix.)
