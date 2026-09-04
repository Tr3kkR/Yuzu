- **Agent OTA update binaries can now be signed, and verified before they run
  (#416, #3807).** The agent previously checked only a SHA-256 that the server
  supplied over the same gRPC channel that delivered the binary — an integrity
  check against corruption, not an authenticity check, since anything able to
  substitute the binary can substitute the hash beside it. The OTA path installs
  and executes code on every managed endpoint, so this was the highest-value
  target in the product. `CheckForUpdateResponse` now carries an optional
  detached PEM CMS signature (a new field, so agents already in the field ignore
  it rather than breaking), and the agent verifies it against a trust bundle
  installed on the endpoint out of band of the update channel — a trust anchor
  delivered by the party being verified anchors nothing. Verification runs after
  the hash check and before anything irreversible: before the execute bit on
  POSIX and before the live binary is moved aside on Windows. It reads the
  already-downloaded file through the descriptor the download was written to, so
  what is verified is provably the bytes at the inode that will be applied — no
  re-open, and therefore no window in which the path could be repointed between
  the check and the apply. On Windows that is required rather than preferable:
  the staged file is opened with `dwShareMode=0` and cannot be opened twice. Configure with `--update-trust-bundle` and
  `--update-require-signature` (both off by default; unset bundle disables
  checking entirely). A signature that is PRESENT and fails to verify is refused
  regardless of the require flag — only an ABSENT signature is tolerated, and
  only while the flag is off. The signature is produced by whoever builds the
  package (`openssl cms -sign -binary -outform PEM`), uploaded alongside it, and
  stored beside it; the server never signs and is not trusted to. The Debian, RPM,
  macOS and Windows packagers now create a dedicated trust-anchor directory
  (`/etc/yuzu-agent/certs`, `%ProgramData%\Yuzu\agent-certs`), which none of them
  did before — deliberately separate from the server's own CA directory, whose
  ownership requirements are incompatible with an agent-readable anchor. On Linux the agent runs unprivileged and cannot write the
  anchor; on macOS and Windows it runs as root and LocalSystem and can, so there
  the permissions keep unprivileged local users out rather than the agent itself
  — inherent, since a process able to replace the system binary can rewrite the
  file authorising the replacement. On Windows the installer takes ownership of
  that directory and rebuilds its permissions outright rather than adding to
  them, because `%ProgramData%` lets an unprivileged user create `agent-certs`
  first: breaking inheritance alone would leave both the entry they had set for
  themselves and their ownership of it, and an owner can restore its own access
  at will. A post-install check then verifies the resulting owner and entry set
  exactly — not merely that inheritance is off — and stops the installation if
  anything other than Administrators and SYSTEM can write there, or if it cannot
  get a definitive answer. Deleting an OTA package writes an
  `ota.package.deleted` audit row naming what actually happened to the binary and
  its signature sidecar, including `result=partial` when the registry row was
  removed but a file could not be. Refusals are counted per agent and
  surfaced fleet-wide as `yuzu_fleet_ota_signature_refusing_agents`, since the
  update path has no status-report RPC and the agent has no metrics endpoint —
  without that gauge a fleet-wide refusal would only be visible in per-endpoint
  logs. **Scope, stated plainly: this closes
  SUBSTITUTION, not ROLLBACK.** The signature covers the binary's content, while
  the version and the hash are still supplied by the server being distrusted, so
  a hostile server can serve a genuinely signed OLD release under a newer version
  label and every agent-side check passes. The attacker is confined to binaries
  the operator's key has signed — a far smaller set than "anything", which is why
  this ships — but not to the intended one; closing that needs the version bound
  into the signed material (a signed manifest) and is tracked separately. See
  "Signing update binaries" in the server administration manual, including why
  the transitional unsigned-allowed mode is a downgrade oracle and why a failing
  agent is currently silent.
