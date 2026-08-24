- **Concurrent quarantine/unquarantine/whitelist calls on the same device can
  no longer race each other (#3286).** Nothing serialized the plugin's
  mutating actions, so two overlapping calls — plausible whenever policy
  evaluation re-fires a quarantine dispatch before the first completes —
  could interleave on the same OS firewall state (e.g. two macOS ruleset
  rebuilds racing over which `pfctl -f` wins). Each of `quarantine`,
  `unquarantine` and `whitelist` now acquires a 2-second-bounded gate before
  touching the firewall; a caller that cannot get in within that budget gets
  an honest `status|busy` rather than racing or hanging. `status` is
  deliberately excluded from the gate — a read must stay available while a
  mutation is in flight, and a mid-mutation read is now honestly reported as
  partial, degraded or uncertain rather than a false `active`.
