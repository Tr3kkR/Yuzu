- **The services plugin no longer reports a truncated macOS service listing as "0 services".** Its
  `list` and `running` actions on macOS previously decoded `launchctl list` output with a private
  parser that skipped the first line without checking it was the header and treated no output at all
  as an empty but successful result. A truncated or corrupted capture was therefore returned as a
  clean, complete listing of zero services. The plugin now uses the same validated parser as TAR, and
  a malformed capture returns `CONSTRAINED` / `PARTIAL` with the provenance
  `services:malformed_launchctl_capture`, so a caller can tell a failed read from a host with nothing
  running.
