- **A reserved-namespace refusal on the instruction-approval gate now answers 400 instead of 500.**
  Executing an approval-gated instruction mints an approval ticket, and if that definition's id is
  under the reserved `mcp.` prefix the mint is refused (#2442) — but the route reported it as a
  generic "failed to create approval request" 500, which reads as a server fault rather than the
  deterministic, renameable config problem it is. The refusal is now a 400 naming the reserved
  prefix and carrying a remediation. The accompanying upgrade note has also been corrected: it
  previously said such a definition "keeps executing", which is true only when its `approval_mode`
  is `auto`.
