- **Windows quarantine no longer strands whitelisted addresses behind an
  unbeatable Block rule (#3284).** A live probe against a physical network
  path (docs/quarantine-windows-firewall-precedence.md) confirmed Windows
  Firewall's Block rules override Allow rules regardless of specificity, so
  the plugin's per-IP and loopback Allow rules were silently inert once the
  blanket `BlockAllInbound`/`BlockAllOutbound` rules went live — a
  quarantined host lost its own management channel, the exact failure
  quarantine exists to avoid. `quarantine` now blocks via the all-profiles
  firewall policy default instead of a rule, so the loopback and whitelist
  Allow rules — unchanged — finally take effect. The pre-quarantine policy is
  captured, reported (`prior_policy|`) and durably stored, and `unquarantine`
  replays it per profile as a failure-tracked step, so a host whose admin or
  GPO had hardened its profile defaults is no longer silently downgraded to
  the Windows default by one quarantine/release cycle. Only a complete
  three-profile capture is stored; anything less falls back to the Windows
  default and says so on both channels rather than replaying a fragment.
- **Windows quarantine status now reads both directions, not just inbound
  (#3285).** `status` previously captured only `dir=in` firewall rules, so a
  failure applying an outbound-only rule was invisible — the device would
  report fully quarantined regardless. It now captures and combines both
  `dir=in` and `dir=out`, reporting `partial` with the missing item(s) named
  whenever the all-profiles block policy and the two loopback Allow rules
  are not every one present.
