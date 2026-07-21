- **macOS antivirus posture is now probed, not asserted.** The `antivirus`
  plugin's macOS `products` leg hardcoded `av|XProtect|active` without reading
  anything and grepped the wrong CrowdStrike process name. It now probes the
  XProtect definition bundle (`av|XProtect|active` + `xprotect_version|<n>`,
  or `unknown` when unreadable — never assumed active) and enumerates
  endpoint-security system extensions for third-party EDR/AV (`av|<name>|
  <active|installed>` + `edr|<bundle id>|<version>`), with corrected process
  fallback. The `status` action on macOS returns XProtect definition
  version/freshness plus Remediator/MRT versions instead of `not_available`,
  exposed via the new darwin-only `security.antivirus.xprotect_status`
  definition.
