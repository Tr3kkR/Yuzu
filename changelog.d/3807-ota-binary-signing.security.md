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
  already-downloaded file through the same descriptor that was hashed, so the
  bytes verified are provably the bytes that were checked, and because the
  staged file is opened with `dwShareMode=0` on Windows that is required rather
  than merely preferable. Configure with `--update-trust-bundle` and
  `--update-require-signature` (both off by default; unset bundle disables
  checking entirely). A signature that is PRESENT and fails to verify is refused
  regardless of the require flag — only an ABSENT signature is tolerated, and
  only while the flag is off. The signature is produced by whoever builds the
  package (`openssl cms -sign -binary -outform PEM`), uploaded alongside it, and
  stored beside it; the server never signs and is not trusted to. The Debian,
  macOS and Windows packagers now create a dedicated trust-anchor directory
  (`/etc/yuzu-agent/certs`, `%ProgramData%\Yuzu\agent-certs`), which none of them
  did before — deliberately separate from the server's own CA directory, whose
  ownership requirements are incompatible with an agent-readable anchor. On Linux the agent runs unprivileged and cannot write the
  anchor; on macOS and Windows it runs as root and LocalSystem and can, so there
  the permissions keep unprivileged local users out rather than the agent itself
  — inherent, since a process able to replace the system binary can rewrite the
  file authorising the replacement. See "Signing update binaries" in the
  server administration manual, including why the transitional unsigned-allowed
  mode is a downgrade oracle and why a failing agent is currently silent.
