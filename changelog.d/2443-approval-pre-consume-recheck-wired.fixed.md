- **`confirm_engine_rotation`'s approval ticket now closes most of the drift-burn gap #2443's
  pre-consume recheck seam was built for.** The seam shipped unwired in an earlier release (no
  caller passed a precondition, so no ticket was protected). This wires the first one: before
  consuming a `confirm_engine_rotation` approval, the MCP recall now rechecks the rotation's
  live state via the same read-only classifier `ApiTokenStore::confirm_rotation` uses under its
  advisory lock (a weaker, unlocked read that narrows the drift window rather than closing it -
  the CAS and the handler's own in-transaction recheck remain the authoritative guards), and
  additionally verifies the active-credential pair is actually linked to and pinned by the
  ticket's own `token_id` (not just "two active credentials exist" - a newer, unrelated rotation
  would otherwise pass the same count check and still burn the ticket at `confirm_rotation`'s own
  pin check). If the rotation already resolved (confirmed, revoked, cut over, an anomalous
  credential count, or a pin mismatch against a newer rotation), the recall denies WITHOUT
  consuming: the ticket stays approved and recallable, instead of the pre-#2443 "approval already
  used" wording that would have misdescribed a still-good ticket. The client-facing denial is
  deliberately generic (no rotation-state specifics) because this precondition runs before the
  tool's own RBAC check; the specific reason is still recorded in the audit row, which - along
  with the existing refusal-rate counter - already covers every consume-failure kind via the
  shared recall path, so this needed no new metric/audit plumbing, only the message split.

  **Not closed by this change:** a process restart evicting the rotation's initiator (grace-cache)
  binding. That state lives in an in-process cache private to `ApiTokenStore` and isn't visible
  to the precondition's read; a ticket recalled after that specific drift still gets consumed and
  then fails at `confirm_rotation`'s own in-transaction check. Tracked as #2946 (a read-only
  accessor for the initiator binding would close it here too). Chaos-scenario coverage for this
  precondition's read pinning an httplib worker is tracked as #2947.
