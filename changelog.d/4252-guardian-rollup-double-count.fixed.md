- **Guardian dashboard compliance % no longer double-counts Linux Service Guards**
  (#4252). The fleet/by-guard/by-baseline census and the per-guard/per-baseline detail
  pages treated every non-Windows agent as "not implemented" for every Guard type — correct
  for Registry/File (genuinely Windows-only), but wrong for Service, which arms
  (observe-only) on Linux too. A Linux agent with a real compliant/drifted status row for a
  Service rule was folded into that rule's "not implemented" bucket a second time,
  corrupting the headline "% compliant" and the fleet/by-baseline breakdowns. The platform
  support check is now guard-type-aware (Registry/File = Windows only; Service = Windows +
  Linux, not macOS), and every render site excludes an (agent, rule) pair that already owns
  a real status row from the synthetic "not implemented" fold. The fleet honesty banner is
  now pair-level (an agent is flagged only if it owns an actually-unenforced pair, not
  merely for being on a platform Guardian doesn't fully support everything on) and its copy
  no longer claims a blanket "Windows only" capability.

  Known accepted limitation: a deployed Service rule targeting a Linux agent whose guard
  never arms (no system D-Bus — this includes every containerized/compose agent, including
  this repo's own reference UAT rigs — a disabled build flag, or an invalid unit name) now
  vanishes from the denominator entirely rather than being flagged "not implemented", since
  the platform is genuinely supported and the agent simply never reported. This has the same
  shape as today's silent omission of any other unreported pair (e.g. an unreported Windows
  pair), so it is not a new class of problem, but it means such a pair is not currently
  visible on the dashboard at all. A `yuzu_server_guardian_platform_matrix_stale_total{spark_type}`
  counter now fires (render-time only, at the fleet and baseline-page views) if the
  hardcoded support matrix ever again disagrees with what an agent actually reports —
  the label is folded to `unknown` for any non-canonical `spark.type`, keeping it the
  closed set the metric docs already claimed. This limitation is deliberately NOT filed
  as its own follow-up issue: it is accepted-by-design (the alternative — inventing a
  "guard never armed" status distinct from "never reported" — is a larger, separate
  behavior change to the agent/server status contract, not a bug in this fix), and is
  fully covered by a regression test pinning the current, intended behavior.

  Known accepted limitation, adversarial-review-identified, tracked as a follow-up issue
  (not fixed in this PR): the new per-pair "already has a real status row" exclusion
  cannot tell a row that is current for the rule's present guard type/platform apart
  from one left behind by an earlier revision of the *same* `rule_id`. If an operator
  re-authors an existing rule's `spark.type` to one unsupported on a target agent's
  platform (e.g. Service → Registry on a Linux-targeted rule) and the replacement guard
  fails to arm, the agent emits no new status, the prior compliant/drifted row survives,
  and the dashboard now shows that pair as compliant with no "not implemented" marker —
  where before this fix it was double-counted (visibly wrong, but at least visible). The
  `..._platform_matrix_stale_total` counter above DOES fire on this exact condition
  (checked: the call site fires it whenever the exclusion suppresses an otherwise-notimpl
  pair, regardless of why the status row exists), so it is not undetectable, just not
  dashboard-visible on the specific affected rule. The root cause — `update_rule()` never
  invalidates `guardian_agent_rule_status` rows on a revision, unlike `delete_rule()`,
  which does — predates this PR and lives entirely in `guaranteed_state_store.cpp`, which
  this diff does not touch; fixing it (version- or platform-binding status rows, or
  invalidating them transactionally on `update_rule`) is store-schema work that belongs
  in its own PR — tracked as #4263.

  **Security hardening (governance review, this same PR):** the shared exclusion
  predicate's (agent_id, rule_id) composite key was originally a delimiter-joined string
  (`agent_id + '\x1f' + rule_id`). Three independent governance reviewers
  (security-guardian, architect, compliance-officer) confirmed neither `agent_id`
  (client-supplied at Register, length-checked only) nor `rule_id` (operator free text on
  the REST create path, no shape validation) is guaranteed free of the separator byte, so
  a crafted pair could collide with an unrelated pair's real status row and silently drop
  the crafted pair from every compliance bucket. Fixed by replacing the string key with a
  `PairStatusKey` struct + hash functor (no delimiter to collide on, for any byte
  content), pinned by a regression test. The new diagnostic log line's `agent_id`/`rule_id`
  interpolation is also now passed through this codebase's existing `log_safe()` helper,
  closing a related log-forging angle on the same unvalidated-charset fact.
