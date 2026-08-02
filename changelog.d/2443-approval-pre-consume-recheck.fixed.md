- **Approval tickets gain a pre-consume recheck seam, so a recall can refuse without spending the
  ticket.** An MCP approval ticket sits approved-but-unconsumed for up to its 7-day TTL, and if the
  state its effect assumes moves on in the meantime (a key rotation resolving before its confirmation
  is recalled, say) the recall matches, consumes the ticket, and only then fails in the handler —
  spending a human-approved one-time capability on a no-op. `ApprovalManager::consume_ticket` now
  accepts a read-only precondition evaluated after the ticket matches and before it is consumed; a
  denial leaves the ticket untouched and still recallable. **No caller passes one yet**, so no ticket
  is protected by this release: the MCP recall is wired in a follow-up, because that file is frozen
  for a parallel change. When it is wired, the protection narrows the drift window rather than
  closing it — the state being rechecked lives outside the approval store, so it can still move
  between the recheck and the consume.
