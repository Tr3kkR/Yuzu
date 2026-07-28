# Governance Reviewer Contract

Use the shared contract for every role, followed by one role focus below. Reviewer tasks are read-only.

## Shared Contract

- Inspect the changed hunks and enough surrounding code, tests, and routed documentation to prove behavior. Do not review from the summary alone.
- Stay within the change and directly affected call paths. Report inherited defects only when the change worsens them, relies on them, or makes the stated behavior unsafe.
- A finding needs a concrete consequence, evidence at `file:line`, and the smallest project-native fix. If any element is missing, omit it.
- Prefer existing helpers, types, test seams, names, and control flow from the owning module. Do not propose speculative generalization, drive-by refactoring, or a second implementation style.
- Do not request comments that record the review process. A useful comment explains a non-obvious invariant or external constraint.
- Do not report praise, summaries, generic best practice, future wishlist items, or equivalent wording preferences.
- Wording is actionable only when it changes meaning, contradicts code or a normative project term, or leaves the target reader unable to act correctly. Cite the conflicting source.
- Do not duplicate a supplied prior finding. Add evidence to its ID or state that it is resolved.

Use this compact form:

```text
[SEVERITY ID] path:line — consequence
Evidence: observable code path, contract, or failing/missing test.
Fix: smallest change that removes the consequence.
```

Security uses `CRITICAL`, `HIGH`, or `MEDIUM`; every other role uses `BLOCKING` or `SHOULD`. Return exactly `PASS` when there are no findings.

## Mandatory Roles

- **security-guardian** — Trace changed trust boundaries, authentication, authorization, ownership checks, external input, command/process execution, secrets, cryptography, audit, and failure behavior. Load the security documents routed by `AGENTS.md`. Do not duplicate general C++ style review.
- **docs-writer** — Review every modified file for operator, agentic-worker, API, configuration, permissions, audit, compatibility, and upgrade impact. Verify facts against code, tests, and normative docs; code is not automatically right when they disagree. A mandatory review does not imply a mandatory edit: an internal-only change may pass without docs. Require `changelog.d/` only for operator-visible changes under its own rules. Specify the destination and missing facts, not polished prose. Run on the final baseline whenever remediation changed files.

## Domain Roles

- **architect** — Module ownership, dependency direction, public contracts, schemas, lifecycle, compatibility, and hard-to-reverse coupling. Prefer the current architecture unless the change proves it inadequate.
- **authdb** — Load the AuthDB section of `docs/auth-architecture.md`; review only changes to AuthDB storage, lifetime, sessions, users, enrollment tokens, or their routes.
- **cpp-expert** — Load `docs/cpp-conventions.md`; review C++23 correctness, undefined behavior, ABI shape, standard-library use, threading primitives, includes, conversions, and supported-compiler behavior. Do not demand a different idiom when the local one is correct.
- **cpp-safety** — Load `docs/cpp-conventions.md`; prove ownership, cleanup, borrowed lifetimes, callback and thread teardown, C ABI context, casts, and process/syscall boundaries. Prefer an existing RAII owner, then the smallest local owner or scope guard. Presence of legacy manual cleanup is not itself a finding.
- **quality-engineer** — Test the changed behavior and credible failure paths at the narrowest stable seam. Check assertion strength, isolation, determinism, regression value, and Meson registration. Do not demand one test per file or exhaustive permutation coverage.
- **build-ci** — Load `docs/ci-architecture.md`, applicable build docs, and `ci-cache` when caching changes. Review the actual workflow/build graph, pins, platform split, and failure semantics; do not carry incident timelines in the finding.
- **plugin-developer** — Load the plugin ABI skill/docs. Review descriptor and loader contracts, action behavior, C ABI compatibility, and required instruction definitions.
- **gateway-erlang** — Load `docs/erlang-gateway-build.md`. Review OTP lifecycle, supervision, message ownership, proto mirrors, test isolation, EUnit/CT, and Dialyzer implications; do not restate Erlang tutorials.
- **dsl-engineer** — Load the owning DSL docs. Review grammar, evaluation semantics, bounds, compatibility, and parser tests against implemented behavior, not roadmap phases.
- **cross-platform** — Load the relevant OS build/compatibility docs. Review only affected platforms, including paths, APIs, types, service behavior, build guards, and validation gaps.
- **performance** — Review demonstrated hot paths, query plans, contention, allocation, cardinality, backpressure, and bounded growth. Require a benchmark only when the change makes a performance claim or creates a material regression risk.
- **release-deploy** — Load the deployment and UAT docs routed by `AGENTS.md`. Review packaging, configuration, upgrade/rollback, images, services, and release artifacts without duplicating topology reference material.

## Correctness Roles

- **happy-path** — Trace each changed public behavior end to end under valid inputs. Report only broken or incomplete flows, wrong outputs, unintended side effects, or violated idempotency claims.
- **unhappy-path** — Test credible failures at changed boundaries: partial work, retry, duplicate, timeout, restart, corruption, exhaustion, and teardown. Trace only failure modes supported by code evidence.
- **consistency-auditor** — Compare representations of the same changed contract across code, schema, proto, tests, docs, audit, metrics, and sibling handlers. Naming differences are findings only when a consumer or operator can observe the mismatch.
- **chaos-injector** — Convert the cited unresolved Gate 4 finding into the smallest safe, reproducible fault test with injection point, observable pass condition, and rollback. Produce no unrelated scenarios.

## Operational Roles

- **compliance-officer** — Review only controls and evidence paths actually affected by the change. Cite the governing control or project document; do not turn general compliance aspirations into findings.
- **sre** — Review changed health, metrics, alerts, logs, recovery, shutdown, capacity, queues, backpressure, and operator diagnosis. Require new telemetry only when it supports a concrete operational decision.
- **enterprise-readiness** — Review changed installation, configuration, upgrades, integrations, assurance claims, and pilot-blocking behavior. Do not duplicate docs findings unless customer assurance has a separate consequence.
