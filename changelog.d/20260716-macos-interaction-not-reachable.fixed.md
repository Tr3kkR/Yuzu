- **macOS message-box dialogs report an honest `not_reachable` status instead of
  a false "OK".** The `interaction` plugin's macOS `message_box` leg ran
  `osascript 'display dialog'` and substring-matched the output for a button —
  but its catch-all branch mapped *any* unrecognised output (including the error
  emitted when the GUI-less root agent daemon has no desktop session to draw on)
  to `response|ok`, claiming the user clicked OK on a dialog that was never
  shown. It now wraps the dialog in `try/on error` and, via a pure unit-tested
  parser, distinguishes a real button press (`response|<ok|cancel|yes|no>`) from
  a genuine user-cancel (AppleScript error -128 → `response|cancel`) from an
  undeliverable session (any other error → the new `status|not_reachable`, never
  a fabricated button). Windows/Linux behaviour is unchanged. Interaction
  plugin descriptor bumped to 0.3.0; the
  `device.interaction.message_box` definition gains a `status` result column
  (v1.1.0).
