- **`confirm_engine_rotation`'s approval ticket now closes the drift-burn gap #2443's
  pre-consume recheck seam was built for.** The seam shipped unwired in an earlier release (no
  caller passed a precondition, so no ticket was protected). This wires the first one: before
  consuming a `confirm_engine_rotation` approval, the MCP recall now rechecks the rotation's
  live state via the same read-only classifier `ApiTokenStore::confirm_rotation` uses under its
  advisory lock (a weaker, unlocked read that narrows the drift window rather than closing it —
  the CAS and the handler's own in-transaction recheck remain the authoritative guards). If the
  rotation already resolved (confirmed, revoked, cut over, or an anomalous credential count),
  the recall denies WITHOUT consuming: the ticket stays approved and recallable, and the caller
  is told the state moved and to retry or re-mint, instead of the pre-#2443 "approval already
  used" wording that would have misdescribed a still-good ticket. The audit row and the
  refusal-rate counter both already covered every consume-failure kind via the shared recall
  path, so this needed no new plumbing there — only the client-facing message split.
