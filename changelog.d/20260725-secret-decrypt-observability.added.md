- **Envelope-encrypted secrets now emit audit events and a Prometheus metric on decrypt failure.**
  `yuzu_server_secret_decrypt_failures_total{store,failure_class}` counts failures by class
  (tamper-detected, unresolvable KEK, malformed blob), and the KEK lifecycle verbs
  (`kek.generated`, `kek.rotated`, `kek.retired`) plus `secret.decrypt_failure` are written to the
  audit log. Required by ADR-0010 for the first store to hold envelope-encrypted secrets at rest
  (the auth store's TOTP secrets); without it a fleet could fail every MFA decrypt with no signal.
