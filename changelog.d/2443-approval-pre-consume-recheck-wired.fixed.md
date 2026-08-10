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
  pin check). If the rotation already resolved (confirmed, revoked, an anomalous credential count,
  or a pin mismatch against a newer rotation), the recall denies WITHOUT consuming: the ticket
  stays approved and recallable, instead of the pre-#2443 "approval already used" wording that
  would have misdescribed a still-good ticket. An empty active-credential read - ambiguous between
  a genuine revoke-to-zero and a masked store fault - also denies rather than passing through:
  denying never consumes, so treating that ambiguity conservatively costs nothing under either
  cause. The client-facing denial is deliberately generic (no rotation-state
  specifics, and points the caller at `get_engine_principal` to check current state) because this
  precondition runs before the tool's own RBAC check; the specific reason is still recorded in the
  audit row. A new `yuzu_mcp_approval_precondition_denied_total` counter breaks this denial class
  out from the shared refusal-rate counter - safe to label by kind (unlike the shared counter)
  because a precondition denial is already distinguishable to the caller from the response body.
  `ApiTokenStore::list_active_for_principal`'s two previously-silent failure branches (pool-lease
  timeout, query failure) now log a warning, closing the "zero log lines" gap a persistent read
  fault would otherwise leave for on-call.

  **Not closed by this change:**
  - A process restart evicting the rotation's initiator (grace-cache) binding. That state lives in
    an in-process cache private to `ApiTokenStore` and isn't visible to the precondition's read; a
    ticket recalled after that specific drift still gets consumed and then fails at
    `confirm_rotation`'s own in-transaction check. Tracked as #2946 (a read-only accessor for the
    initiator binding would close it here too).
  - Two independently-approved tickets pinned to the same successor `token_id` (an operator
    double-approval mistake): both preconditions read the identical linked/pinned state
    concurrently, both pass, both consume (different approval rows), and only one `confirm_rotation`
    call wins the advisory lock - the loser's ticket is already burned before its own confirm fails.
    Known and accepted; deterministic regression-test coverage tracked as #2952.
  - Chaos-scenario coverage for this precondition's read pinning an httplib worker under a
    black-holed database connection is tracked as #2947.
