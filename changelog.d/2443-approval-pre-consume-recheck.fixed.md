- **An MCP approval ticket can no longer be burned by state that drifted while it
  waited.** A ticket sits approved-but-unconsumed for up to its 7-day TTL, and if the
  state its effect assumes moves on in the meantime (a key rotation resolving before its
  confirmation is recalled, say) the recall used to match, consume the ticket, and only
  then fail in the handler — spending a human-approved one-time capability on a no-op.
  `ApprovalManager::consume_ticket` now accepts a read-only precondition evaluated after
  the ticket matches and before it is consumed; a denial leaves the ticket untouched and
  still recallable once the operator resolves the drift. This narrows the drift window
  rather than closing it: the state being rechecked lives outside the approval store, so
  it can still move between the recheck and the consume.
