- **MCP approval recall is now bound to the ticket's own submitter.** An approval id is a
  bearer capability — presenting it is what authorizes an MCP tool recall — and `GET
  /api/approvals` discloses the full id to any principal holding `Approval:Read` (seeded to the
  `Viewer` role). A Viewer who also held a gated tool's own RBAC permission could take another
  operator's approved ticket id from that listing and redeem it themselves, spending a human
  approval the reviewer never intended for that principal. The recall now refuses a ticket whose
  recorded submitter does not match the recalling principal — checked in the same store read as
  the existing cross-surface origin check (#2442), so no new query and no change to the
  same-connection SELECT ordering the chaos-test coverage depends on. Refused exactly like an
  ordinary spent ticket to the caller (`approval already used (one-time ticket)`); the audit
  trail records the distinct cause as `refused: foreign_submitter`, and
  `yuzu_mcp_approval_masked_denials_total` covers a store fault at this same check the same way
  it already covers one at the origin check. An intentional security-tightening compatibility
  break, not expected to affect any supported flow: the sole production redemption path in this
  codebase has only ever redeemed a ticket as the principal that minted it, verified by an
  exhaustive sweep of every mint/consume call site — but that proves no in-tree delegation path,
  not that no external integration ever relied on handing an `approval_id` to a different
  principal. Delegated recall does not exist anywhere in this codebase today, so a straight
  equality is the correct binding here, not a placeholder for a delegation model this release
  does not need; an integration that needs one should file it rather than work around the
  refusal.

  Related, separately tracked: #1803, the disclosure half this closes only a consequence of — the
  full id is still returned by `GET /api/approvals` to any `Approval:Read` holder. Either fix
  narrows the exposure on its own; #1803 is the heavier, ADR-0017-adjacent
  management-group-confinement question.
