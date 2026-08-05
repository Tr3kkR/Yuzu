- **Every shipped plugin now declares its per-OS capabilities; the capability-matrix ratchet
  floors at zero.** All 49 plugins populate the ABI4 `action_descriptors` array (180 entries,
  540 table rows), so `docs/os-capability-matrix.md`'s generated block lists no undeclared
  plugins and `RATCHET_BASELINE_UNDECLARED` in `scripts/ci/check-capability-matrix.sh` drops
  from 49 to 0. At zero the ratchet is equivalent to a hard fail: a new plugin directory landing
  without descriptors grows the count and fails the Linux leg. `capmatrix-gen` additionally
  hard-errors on any mismatch between a plugin's `actions()` list and its declared descriptors
  before writing, so a declaration that silently omits an action cannot reach the table.
