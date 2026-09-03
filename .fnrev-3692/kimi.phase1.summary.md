• empiricism unavailable this run (read-only static-bundle mode) — review is static-read only; all findings tagged accordingly except where citing the orchestrator EVIDENCE verbatim.

  ---

  # kimi phase1 — functional verification of `fix/3692-ota-rollout-audit`

  **Fixed point:** `origin/dev...HEAD` @ `90f830448`, merge-base `fd81b290`. 5 files, +257 (30 production C++ in `settings_routes.cpp` / `update_registry.{cpp,hpp}`).

  ## Behaviour inventory

  - **B1** — The OTA rollout route (`POST /api/settings/updates/{platform}/{arch}/{version}/rollout`) now emits an audit row on **every** admin-gated invocation: `audit_fn_(req, "ota.package.rollout_changed", result, "UpdatePackage", "<platform>/<arch>/<version>", detail)`. Pre-change: no `audit_fn_` call at all (the `#3692` gap).
  - **B2** — Success branch: package found **and** registry write committed → `result=success`, `detail="from=<prior>% to=<clamped new>% mandatory=<bool>"`, where `from=` is the pre-write stored value and `to=` is the clamped stored value.
  - **B3** — Not-found branch: no matching package → nothing mutated, `result=denied`, `detail="not_found"` (rejection vocabulary chosen to match the file's other denial rows and the `result == "denied"` SIEM filter).
  - **B4** — Found-but-not-committed branch: `upsert_package` now returns `bool` and the handler derives `result` from it — `result=failure`, `detail="registry write did not commit; rollout unchanged"`, plus a new `spdlog::error`. Previously the degrade paths (closed store, pool timeout, query error) logged and returned `void`, and the handler had no way to know.
  - **B5** — `UpdateRegistry::upsert_package` signature change: `void` → `[[nodiscard]] bool`, `false` on exactly the three degrade paths. Compile evidence (0 errors) shows all callers adopted.
  - **B6** — Upload route: `(void)` cast added on its `upsert_package` call. No runtime behaviour change; upload/delete audit lives in #3929 per the scope note (correctly not duplicated here).

  Docs (`audit-log.md` row, changelog fragment) document B2/B3's contract; they carry no behaviour.

  ## Evidence check

  - Compile `yuzu_server_tests`: 0 errors — covers all changed TUs (`settings_routes.cpp`, `update_registry.cpp`).
  - Targeted suite `[ota][audit]` with real PG: **"All tests passed (33 assertions in 3 test cases)"** — see F1; the diff contains **four** `TEST_CASE`s.
  - Mutation probes corroborate discrimination: P1 (remove `audit_fn_` call → 3 assertions failed), P2 (misreport `from=` → 2 failed), P3 (always `success` → 1 failed). P1's count of exactly 3 is only consistent with 3 test cases executing, matching the suite count — see F1.

  ## Coverage map

  | Bn | Test (file: case) | Key assertions | Survives revert? |
  |---|---|---|---|
  | B1+B2 | `test_settings_routes_ota_audit.cpp` — "OTA rollout change is audited with the value it changed FROM (#3692)" | `audited.size()==1`; `action`/`result=="success"`/`target_type`/`target_id=="linux/x86_64/1.2.3"`; `detail` contains `from=100%`, `to=0%`, `mandatory=true`; stored `rollout_pct==0` | No — pre-change code never calls `audit_fn_`, so `REQUIRE(audited.size()==1)` fails. Discriminating. |
  | B3 | "…records not_found, not success" | `result=="denied"`, `detail=="not_found"`, `target_id` of the phantom package, seeded package untouched (`rollout_pct==50`) | No — same empty-`audited` failure. Discriminating. |
  | B4+B5 | "a rollout whose registry write does not commit is audited as failure, not success" | CHECK constraint violates only the write (SELECT keeps working — the comment documents why the first drop-table version was a false-green); asserts `result=="failure"`, no `from=` in detail, stored value still 100 | No — no audit call pre-change. Discriminating by construction. **Execution unconfirmed — F1.** |
  | B6 | none needed | No behaviour delta; `(void)` cast is compile-level; covered by the clean compile. | N/A |

  Clamp behaviour (part of B2) is separately pinned by "OTA rollout percentage is clamped, and the row reports the CLAMPED value" (`from=10%`/`to=100%`, stored 100).

  ## Revert-reasoning summary

  Each of tests 1–4 hard-depends on the new `audit_fn_` invocation (P1 mutation proves the size REQUIRE fails without it), and each pins a distinct result token (`success` / `denied` / `failure`) plus state verification via `list_packages()` — the state check is what makes a wrong `result` token a failing assertion rather than a string-pin. No revert-survivors found.

  ## Test quality

  - Real PG behind `YUZU_REQUIRE_PG_DB_TPL` with a pre-migrated template clone — matches the repo's established PG-gated route-test convention (same pattern as sibling `test_settings_routes_*.cpp`); tagged `[pg]`, executed per the brief. No sleeps/polls, no wall-clock, no network, no process spawn. Temp dirs use the `yuzu_test_` prefix.
  - Assertions are behavioural (result token, `from=`/`to=` substrings, DB state), not tautologies. Test 4's injection design (constraint that breaks only the write) is explicitly defended against the false-green variant.
  - Minor: test 3 doesn't `REQUIRE(res)` — immaterial, since the audit and state asserts carry the load.

  ## Findings

  ```
  [F1]  MEDIUM · CONFIDENCE med · PROVENANCE evidence
  Evidence executed 3 of 4 test cases — failure-path execution unconfirmed
  - Behaviour: B4 (found-but-not-committed -> result=failure)
  - Location:  tests/unit/server/test_settings_routes_ota_audit.cpp (4th TEST_CASE,
               "a rollout whose registry write does not commit is audited as failure")
  - Claim:     The targeted suite reports "33 assertions in 3 test cases" and mutation
               probe P1 (audit_fn_ call removed) failed exactly 3 assertions, yet the
               diff registers FOUR TEST_CASEs, each opening with REQUIRE(audited.size()==1)
               which must fail when the call is removed. Both counts are consistent only
               with one test case — most plausibly the B4 failure-path case, the one
               covering the new bool-return derivation — never executing in the evidence
               run. If so, B4 rests on static-read only.
  - Evidence:  EVIDENCE block lines "All tests passed (33 assertions in 3 test cases)" and
               "P1 remove the audit_fn_ call -> 3 assertions failed"; diff shows 4
               TEST_CASEs with identical [ota][audit][settings_routes][pg] tags.
  - Fix:      None to the code — re-run the suite with per-case listing (probe below); if
               a filter/skip dropped one case, fix the run invocation, not the tests.
  - Falsifier: PR-kimi-1 — a listing + verbose re-run showing 4 test cases executed and
               passing refutes this finding.
  ```

  ```
  [F2]  LOW · CONFIDENCE hi · PROVENANCE static-read
  New non-commit error log line is unasserted (acceptable)
  - Behaviour: B4's spdlog::error side effect
  - Location:  server/core/src/settings_routes.cpp (rollout hunk)
  - Claim:     The "OTA rollout NOT applied ..." error log has no assertion; harmless
               since the audited row is the tested contract. Noted for completeness only.
  ```

  ## Probe requests

  ```
  [PR-kimi-1]  priority med · proves-or-refutes: F1 / B4
  - Probe:    ./build-macos/tests/yuzu_server_tests --list-tests "[ota][audit]"
              then ./build-macos/tests/yuzu_server_tests "[ota][audit]" -r compact -s
              (PG DSN per evidence block)
  - Expected: 4 test cases listed and 4 reported passing => F1 refuted, B4 evidence-grade.
              3 listed/run => name the missing case and why it was filtered/skipped;
              B4 stays static-read-only.
  ```

  ```
  VERDICT: PASS — every inventory behaviour has a discriminating test whose assertions fail under revert (corroborated by mutation probes P1–P3) and the changed TUs compile clean; the only open item is the 3-vs-4 test-case count in the evidence (F1, MEDIUM), settled by PR-kimi-1.
  BEHAVIOURS: 6 identified / 5 proven-by-existing-test / 1 pending-probe (B4 execution confirmation) / 0 unproven (B6 is a no-behaviour-change, compile-covered)
  PROBES: 1 requested (PR-kimi-1)
  FILES: changelog.d/3692-ota-rollout-audit.security.md; docs/user-manual/audit-log.md; server/core/src/settings_routes.cpp; server/core/src/update_registry.cpp; server/core/src/update_registry.hpp; tests/meson.build; tests/unit/server/test_settings_routes_ota_audit.cpp
  ```

  *(Write is disabled in this restricted run — the runner should persist the document above as `.fnrev-3692/kimi.phase1.md`.)*

