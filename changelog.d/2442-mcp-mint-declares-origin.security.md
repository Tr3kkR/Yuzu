- **Breaking — the MCP approval mint now declares its own minting surface, closing the
  redemption-side gap the cross-surface binding left open.** Since #2442's origin column
  landed, a ticket recorded as minted by a declared non-MCP surface (`kInstruction`,
  `kSchedule`) was refused at the MCP recall — but the MCP mint itself still went through the
  undeclared path, and an undeclared ticket was the one case the guard deliberately let
  through, because the MCP gate could not yet declare itself. It now mints every ticket with
  `ApprovalOrigin::kMcp` explicitly, and `ApprovalManager::submit`'s `origin` parameter is no
  longer defaulted, so a future caller cannot silently regain the old exemption by omitting
  the argument — it is a compile error instead.

  **What breaks:** an undeclared origin (`ApprovalOrigin::kUnspecified` — an empty `origin`
  column, or a row that predates the column and decoded to it) is no longer redeemable at the
  MCP recall; it now refuses exactly like a declared foreign surface, reported with the same
  generic "not consumable" message so the recall still cannot be used to fingerprint which
  case applies. **Any MCP approval ticket already minted and still outstanding (pending or
  approved-but-unconsumed) when you upgrade is refused, and must be re-requested** — re-call
  the tool without `approval_id` to mint a fresh, correctly-declared ticket. Scheduled
  approvals are unaffected: `ScheduleRunner` redeems by matching its own schedule id, never
  through the MCP recall, so this guard never sees one.
