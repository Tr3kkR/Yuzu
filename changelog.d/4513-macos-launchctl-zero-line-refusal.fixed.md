- macOS: a zero-line `launchctl list` capture (an exit-0 subprocess result with no
  output at all, distinct from a genuine "no services" answer, which always includes
  at least the header row) is now treated as a corrupted/truncated capture rather than
  a valid empty snapshot. TAR's service source refuses the diff and retains the
  previous baseline instead of reading it as "every previously-known service just
  disappeared" — which previously would have stormed every service back as freshly
  `added` on the next real capture.
