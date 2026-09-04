- **Changing an OTA update's rollout percentage is now recorded in the audit log
  (#3692).** The route that decides which endpoints receive a given agent binary
  gated correctly on admin, then wrote only to the application log — so "who
  de-prioritised this security patch, and when" was not answerable from the audit
  trail an incident responder or SOC 2 auditor reads. The new
  `ota.package.rollout_changed` event records the acting principal, the package
  key, and crucially the value the rollout changed **from**: a package sitting at
  0% looks identical whether it was deliberately pulled back or never rolled out,
  and only the prior value separates them. Requests naming a package the store
  reports as absent are recorded as denied, so key enumeration stays visible
  rather than blending into normal traffic — while a rollout whose write does not
  commit, or one made against a registry that cannot be read at all, is recorded
  as a failure and never as absence. That distinction matters because these reads
  fail soft: without it a database blip during a legitimate rollout would both
  raise enumeration alerts and assert, in the evidence record, that a package
  which exists did not. The recorded prior value is the one the write actually
  replaced: the package row is read under a lock and updated in the same database
  transaction, so a second rollout change to the same package arriving at the same
  moment cannot slip between the read and the write and leave the row naming a
  value it did not replace — which matters precisely because the admin whose
  tracks this evidence exists to preserve is also the one who could issue both
  requests. The rollout write also now touches only the rollout percentage
  instead of rewriting the whole package row, so it can no longer silently revert
  a concurrent change to another field such as the mandatory flag.
