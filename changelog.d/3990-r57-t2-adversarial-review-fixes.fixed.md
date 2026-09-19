- **`#3990` blackout diagnostic driver: fixed five verdict-path bugs, all found by
  `/adversarial-review` (Kimi K3 + Codex Sol) or `/governance`** (happy-path, unhappy-path,
  consistency-auditor, quality-engineer), all the same laundering shape - a genuine reliability
  signal getting silently reclassified instrument-invalid because of check-ordering, not because
  the signal was wrong. A collection-stage instrument-invalid void reason (e.g. `double_full_sync`)
  could suppress an already-known genuine `failed>0` arm failure - this changed the actual
  recorded R5.7 Phase B2 verdict (see the R5.7 T2 results entry above, corrected in place to
  reflect this). The same shape recurred twice more, verified in code though neither had
  manifested in the committed data: `collect_t2()` could let a later, unrelated `double_full_sync`
  mask an earlier genuine `fence_violation` (fixed via `resolve_collect_t2_reason()`), and
  `sweep_incomplete()` could drop a fence-violation signal `sweep_row_pure()` turned up on its
  second look, declaring the row `t2_late` (instrument) instead (fixed via
  `resolve_sweep_reclassification()`). The post-invocation sweep's membership rule also diverged
  from the primary classifier's in both directions (no next-application boundary on legacy, no
  floor/adopt handling on spark); it now reuses the primary classifier directly. `compute_verdict()`
  was missing the pre-registered rule that a cell whose instrument-invalid voids exceed 50% of its
  attempts is INCONCLUSIVE, never PASS. A regression test (`/governance`'s own first pass) for one
  of these fixes was itself found to be false-green (it never exercised the fix it claimed to
  guard) and was rewritten to actually exercise the precedence decision. Selftest extended 14 to
  20 fixtures, each verified in both directions (passes with its fix, fails if the fix is
  reverted).
