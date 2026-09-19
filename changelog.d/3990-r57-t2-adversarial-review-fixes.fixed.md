- **`#3990` blackout diagnostic driver: fixed three verdict-path bugs found by
  `/adversarial-review`** (Kimi K3 + Codex Sol, independently and in cross-examination). A
  collection-stage instrument-invalid void reason (e.g. `double_full_sync`) could suppress an
  already-known genuine `failed>0` arm failure, laundering it into an instrument-invalid void -
  this changed the actual recorded R5.7 Phase B2 verdict (see the R5.7 T2 results entry above,
  corrected in place to reflect this).
  The post-invocation sweep's membership rule diverged from the primary classifier's in both
  directions (no next-application boundary on legacy, no floor/adopt handling on spark); it now
  reuses the primary classifier directly. `compute_verdict()` was missing the pre-registered
  rule that a cell whose instrument-invalid voids exceed 50% of its attempts is INCONCLUSIVE,
  never PASS. Selftest extended 14 to 17 fixtures.
