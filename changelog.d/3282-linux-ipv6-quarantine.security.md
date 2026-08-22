- **Linux `quarantine`/`unquarantine`/`status` now contain IPv6 traffic, not just IPv4 (#3282).**
  The Linux quarantine implementation previously built and read only the `iptables` chain — on a
  dual-stack host, a "quarantined" device could still send and receive IPv6 traffic freely. Every
  mutating step (`quarantine`'s rule sequence, `unquarantine`'s teardown, `whitelist` add/remove)
  and both read paths (`status`'s active/inactive check, the reported whitelist) now mirror the
  same sequence onto `ip6tables`, routing each whitelisted IP to the matching family and never
  handing a v6 literal to `iptables` or vice versa. The IPv6 environment is probed by filesystem
  (`ip6tables` binary present? `/proc/net/if_inet6` present?), never inferred from a sudo-wrapped
  subprocess's exit status, which cannot distinguish "ip6tables ran and failed" from "sudo itself
  never got that far." A host with no IPv6 stack at all reports full `quarantined` containment
  with an explanatory note rather than a permanent false "partial"; a host with an IPv6 stack but
  no `ip6tables` installed correctly reports a partial containment gap instead of a clean
  "quarantined" that silently leaves IPv6 traffic unblocked. On a dual-stack fleet, whitelist the
  management server's IPv6 address as well as its IPv4 address — the two chains are independent,
  and a live connection held open only by IPv4's `ESTABLISHED,RELATED` rule can be dropped by the
  IPv6 chain on the next reconnect if only the v4 address was whitelisted.
- **The `quarantine` action's success gate no longer treats any single applied rule as "quarantined"
  (#3260).** `rules_applied > 0` — true even when the loopback ACCEPT rule was the ONLY rule that
  applied and every containment rule after it failed — is replaced with an honest
  attempted-vs-succeeded tally per firewall family: `status|quarantined` is emitted only when every
  attempted mutation succeeded, `status|failed` when none did, otherwise `status|quarantined_partial`
  with the true count and an explanatory note. `linux_is_quarantined` now checks both the INPUT and
  OUTPUT jump on both families instead of only the IPv4 INPUT jump, so a host with an INPUT jump but
  no OUTPUT jump (or vice versa) reports partial containment instead of a false "active."
- **The dead `lo` substring filter is gone (#3260).** `iptables -L -n` never reliably rendered
  `-i`/`-o` interface restrictions as visible text, so the loopback-rule exclusion in the whitelist
  parser was matching nothing it claimed to guard against — while occasionally discarding a genuinely
  whitelisted IP whose captured line happened to contain the substring "lo" elsewhere. The loopback
  ACCEPT rule's wildcard source/destination is already rejected by the existing IP-literal
  validation, which is the only guard actually needed.
