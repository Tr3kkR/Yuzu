- `#3990` R5.7 T2 driver (PR #4614 review, Gate-4 unhappy-path): fixed two
  gaps in the `cohort_events_d()` fetch-laundering fix from the prior review
  round, both self-inflicted by that fix's own logic rather than the
  original bug. First, `never_fetched` tracked whether a rule's fetch EVER
  succeeded rather than whether its MOST RECENT attempt did - since the
  polling deadline is sized so the first sweep is expected to find nothing
  for nearly every rule, a rule whose REST access broke immediately after
  that always-empty first success stayed permanently "ok" and any
  subsequent, silently-missed genuine failure got folded into the genuine
  bucket exactly like before, just via a different code path. Second, a
  single never-fetched rule in a cohort voided the WHOLE row as
  instrument, discarding every other rule's reliable evidence - inverted
  from this file's own stated "genuine always wins" doctrine. Extracted
  the row-level decision into `resolve_cohort_void()` (matching this
  file's established pure-function-extraction convention) so genuine wins
  unless every unresolved rule's last look was fetch-tainted. Selftest
  extended 24 to 25 fixtures; F24 rewritten for the corrected last-attempt
  semantics, new F25 covers the row-level precedence fix - both
  mutation-tested.
