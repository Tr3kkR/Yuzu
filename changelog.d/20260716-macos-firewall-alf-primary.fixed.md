- **macOS firewall state now reports the Application Firewall, not pf.** The
  `firewall` plugin's macOS `state` action read `pfctl -s info` — pf is off by
  default and unrelated to the macOS Application Firewall, so a Mac with the
  real firewall on could read `disabled` (and vice versa). `socketfilterfw
  --getglobalstate` is now the primary signal (`backend|appfirewall`,
  `state|…`, plus `mode|block_all` when block-all is set); pf is demoted to a
  secondary `pf|<state>` row. Unreadable checks report `unknown`, never a
  false-safe value.
