- **Changing an OTA update's rollout percentage is now recorded in the audit log
  (#3692).** The route that decides which endpoints receive a given agent binary
  gated correctly on admin, then wrote only to the application log — so "who
  de-prioritised this security patch, and when" was not answerable from the audit
  trail an incident responder or SOC 2 auditor reads. The new
  `ota.package.rollout_changed` event records the acting principal, the package
  key, and crucially the value the rollout changed **from**: a package sitting at
  0% looks identical whether it was deliberately pulled back or never rolled out,
  and only the prior value separates them. Requests naming a package that does
  not exist record `not_found` rather than a fictional success, so key
  enumeration stays visible rather than blending into normal traffic.
