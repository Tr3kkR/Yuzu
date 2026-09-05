- **API parity ledger + conformance gate (ADR-0031 INV-31-4, #3991).** A new
  `docs/api-parity-ledger.md` + `scripts/ci/api-parity/<domain>.json` ledger
  gives every dashboard fragment/legacy route a tracked twin-status row
  (`twinned`, `planned:#N`, `composed-of:...`, `exception:...`, or `retire`
  - most start `planned`, not yet twinned), and `scripts/ci/check-api-parity.py`
  (wired into CI as a preflight step) keeps it honest: it fails on an
  unledgered route, a stale twin claim, an undocumented `/api/v1` route
  outside a seeded allowlist, or the untwinned-row count regressing past a
  ratchet baseline. This is a lexical tripwire (regex extraction, not a C++
  parser) - see `docs/api-parity-ledger.md` "What this is not" for scope. A companion
  `tests/unit/server/test_openapi_spec_completeness.cpp` covers the
  in-process half against `RestApiV1::register_routes()`. This is the
  foundation (F1) of the #2146 programme closing the REST/MCP/dashboard
  parity gap, and a deliberate stopgap for ADR-0032 interlock (j) / #2678's
  future generated-capability-projection diff harness.
