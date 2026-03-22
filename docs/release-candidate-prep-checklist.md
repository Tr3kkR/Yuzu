# Release Candidate Branch Preparation Checklist

This checklist is tailored for the current Yuzu branch and can be reused as a standard RC gate.

## 1) Typical RC Preparation Tasks

### Scope, freeze, and change control
- Create an RC cut date and stop merging non-release-critical features.
- Label and triage all open issues into: must-fix, can-ship, and post-release.
- Enforce a strict exception process for late changes (owner + risk + rollback notes).

### Build, package, and reproducibility
- Build release artifacts for every supported target from a clean checkout.
- Verify deterministic packaging inputs (toolchain pins, dependency locks, submodule state).
- Validate artifact completeness (binaries, plugins, content definitions, checksums, signatures).
- Confirm version stamping (semantic version, build number, commit hash) in binaries and metadata.

### Quality gates
- Run full CI matrix and require green status on the RC commit.
- Run smoke tests on packaged artifacts (not only build-tree binaries).
- Execute integration/regression suites against realistic deployment topology.
- Run installer/upgrade and rollback tests from at least one previous GA version.

### Data and migration safety
- Test all schema migrations forward and rollback (or document non-reversible migrations).
- Verify backup/restore and disaster-recovery runbooks with current schema.
- Validate retention, compaction, and cleanup jobs under production-like data volume.

### Security and compliance
- Run dependency/vulnerability scans and triage all critical/high findings.
- Verify authn/authz controls and least-privilege defaults in release configuration.
- Rotate/review release signing, tokens, and secret management before cut.
- Confirm transport security and certificate handling in production deployment modes.

### Reliability and operations readiness
- Verify health endpoints, alerting rules, and dashboards for release SLOs.
- Execute load and soak testing for key API/control-plane workflows.
- Confirm rate limiting, timeout policies, and backpressure behavior.
- Verify logs include enough context for incident response without leaking secrets.

### Release communications and enablement
- Finalize changelog, release notes, known issues, and upgrade caveats.
- Publish operator/admin runbooks and rollback instructions.
- Prepare support handoff: severity matrix, on-call schedule, escalation path.

---

## 2) “Things teams wish they had done” before release

These are common postmortem regrets and should be explicit RC checks:

- **Run upgrade rehearsals on real data clones** (not only fresh installs).
- **Exercise rollback under pressure** (including partial failures and mixed-version fleets).
- **Freeze dependencies earlier** to avoid last-minute transitive breakage.
- **Perform production-like load/soak tests** long enough to reveal leak/drift issues.
- **Validate observability from the user perspective** (alerts actionable, dashboards meaningful).
- **Do one security abuse-case pass** for token misuse, replay, and privilege escalation paths.
- **Publish known limitations honestly** so support and customers are not surprised.
- **Designate a release commander and clear go/no-go criteria** before launch day.
- **Prepare a hotfix path** (tagging, branching, cherry-pick policy, release automation test).
- **Audit default configs** to ensure safe-by-default behavior in first-time installs.

---

## 3) Items that appear already complete on this branch

Based on repository evidence, these RC readiness capabilities look present:

- **Cross-platform CI matrix exists** (Linux GCC/Clang, Windows MSVC, macOS, debug+release). See `.github/workflows/ci.yml`.
- **Dedicated release automation exists** with multi-platform artifact jobs and release creation. See `.github/workflows/release.yml`.
- **Changelog discipline exists** with SemVer framing and recent versioned entry (`0.1.0`, dated 2026-03-21). See `CHANGELOG.md`.
- **Release builds include LTO paths** in CI/release workflow steps. See `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- **Deployment artifacts are documented/provided** (Dockerfiles, compose, systemd units, Prometheus/Grafana configs). See `deploy/`.
- **Preflight operational validation script exists** for binary presence, ports, disk, dependencies, certs, and connectivity. See `scripts/yuzu-preflight.sh`.
- **Operational docs exist** for upgrade, server admin, security hardening, metrics, REST API, and user manual sections. See `docs/user-manual/`.

---

## 4) Suggested RC blockers or high-priority checks to verify before tagging

Even with strong groundwork, these should be explicitly re-verified for the RC commit:

- CI green on the exact candidate SHA for all required jobs.
- End-to-end upgrade and rollback from prior GA on representative datasets.
- Final triage of open HIGH-severity gateway issues tracked in branch status docs.
- Validation that release notes and known-issues match the exact shipped feature set.
- Confirm signed artifacts/checksums are generated and published as expected.
- Confirm production alert rules and dashboards are wired to real environments.

---

## 5) Practical go/no-go checklist (short form)

Use this at release meeting time:

1. RC branch frozen and exception list approved.
2. CI + release workflow green on candidate SHA.
3. Upgrade + rollback rehearsal passed.
4. Security scan triage complete (no unapproved critical/high risk).
5. Observability and runbooks validated by on-call owners.
6. Changelog/release notes/known issues approved.
7. Named release commander and rollback owner on duty.

If any item is red, do not tag.
