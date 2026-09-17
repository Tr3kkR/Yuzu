- **New live probe for the Windows quarantine Block-vs-Allow precedence question (#3284).**
  `scripts/test/win-quarantine-precedence-probe.ps1` runs on-box against a real Windows Firewall to
  determine whether a narrower `AllowIn_<ip>`/`AllowOut_<ip>` whitelist rule still admits traffic
  once win_quarantine's `BlockAllInbound`/`BlockAllOutbound` rules are applied, measured against a
  physical-path address (default gateway or LAN peer) rather than the Tailscale overlay, which the
  Windows Firewall filters at the physical adapter and would otherwise confound the result. The
  destructive pass is gated behind two independent scheduled-task watchdogs that must each be
  observed removing a real firewall rule — not merely registered — before any Block rule is written,
  and defaults to a non-destructive `-DryRun`. See `docs/quarantine-windows-firewall-precedence.md`
  for the current evidence status.
