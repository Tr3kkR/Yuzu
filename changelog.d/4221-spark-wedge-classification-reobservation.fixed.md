- **Guardian spark (lands dormant: `prefer_spark_` stays false, so no
  production arm or disarm takes the new path until the flip): a
  dispatching-window race no longer misclassifies an ordinary admission
  failure as a stuck key, and a routine same-rule retry onto an already-stuck
  key no longer piles up a fresh, doomed-to-timeout-again claim on every
  re-apply.** A claim's terminal classification could be silently overwritten
  by a stale value from `expire_overdue_claims()` if that call landed in the
  narrow off-lock window between a refill's admission decision starting and
  finishing, at both of the two places this could happen; `ReceiptStatus` now
  distinguishes a claim that merely timed out queued (`CongestionExpired`,
  ordinary backpressure) from one that timed out while dispatching or
  dispatched (`Wedged`, an overdue retained dispatch episode); and an
  identical `(rule_id, spec)` re-apply onto a `Wedged` key now re-observes
  the existing head's own outcome directly instead of queuing a new claim
  behind it, while a genuinely different claimant onto the same key is
  refused immediately rather than waiting out the same doomed queue (#4221).
