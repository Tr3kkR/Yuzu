- **Engine principals are now truly default-deny (#2202).** An external adversarial review of
  the engine-principals PR 4.2 slice found that an engine credential still inherited fleet-wide
  `Read` via the legacy pre-RBAC fallback whenever RBAC was off (the historical default) —
  contradicting the design's "an engine principal with no assignments can do nothing" promise.
  Engine sessions now resolve authority **exclusively** against `RbacStore`: `403` when RBAC is
  disabled or no explicit grant matches, `503` when the RBAC store is unavailable, with no
  legacy or service-scoped fallback under any circumstance. Three related hardening fixes closed
  in the same round: (1) a corrupt `rbac.db` now fails the boot-time `engine:`-namespace
  collision preflight **closed** instead of scanning "clean" past an unreadable store; (2) audit
  rows for engine-principal actions now carry `principal_class=engine` truthfully (previously
  mislabelled `agent`); (3) `upsert_sso_identity` rejects any `engine:`-prefixed identity write
  at the SSO sync surface, closing a reserved-namespace collision path.
