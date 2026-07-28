---
name: governance
description: Run or maintain Yuzu's bounded Codex governance review on a commit range. Produces evidence-backed security, documentation, domain, correctness, and operational findings with a compact ledger. Use for `/governance RANGE`, "full governance", a multi-gate PR review, or an audit of the governance workflow and reviewer prompts.
---

# Governance

Review the exact range with bounded, read-only reviewer fanout. The primary agent owns scope, deduplication, adjudication, and the final decision. Do not expose raw reviewer transcripts.

Before launching reviewers, read [references/reviewers.md](references/reviewers.md) completely. Use its shared contract in every reviewer prompt and append only the matching role focus.

Give each reviewer the resolved range, the compact Gate 1 facts, changed paths, and only prior finding IDs relevant to that role. Do not paste another reviewer's prose.

## Range

- Default to `dev..HEAD`.
- Treat a bare commit as `<commit>~1..<commit>`.
- If `dev..HEAD` is empty on `dev`, ask whether `origin/dev..HEAD` is intended.
- Resolve and record the base and head SHAs before review. A later fix changes the reviewed baseline and triggers only the re-review described below.

## Review Standard

- Review changed behavior and directly affected call paths, not unrelated backlog.
- Load the documents routed by `AGENTS.md`; durable invariants belong there, not in reviewer prompts.
- Compare adjacent production code and tests before proposing a pattern. Prefer the smallest change that fits the owning module. Do not request a rename, abstraction, helper, or modernization without a concrete correctness, safety, duplication, or contract reason.
- For C++ changes, always run `cpp-expert` and `cpp-safety`. Prefer automatic ownership and existing RAII helpers. Add an ownership note only when the range adds a resource boundary or changes acquisition, transfer, release, callback, or thread lifetime.
- Production comments explain the invariant or failure mode. They do not cite governance rounds, agents, or finding IDs.
- Treat wording as a finding only when it is factually wrong, contradicts a normative term or public contract, or is materially ambiguous to its intended reader. Existing nearby terminology wins when several phrasings are equivalent.

## Gates

1. **Summary** — Record range and intent, changed contracts or risks, validation already run, triggered roles, and either `Ownership changes: none` or a compact ownership note.
2. **Mandatory** — Run `security-guardian` and `docs-writer` in parallel on every changed file. Neither role may be skipped.
3. **Domain** — Run only roles triggered by `AGENTS.md`, changed files, or affected contracts. C++ always triggers both C++ roles; a feature or bug fix triggers `quality-engineer`.
4. **Correctness** — Run `happy-path`, `unhappy-path`, and `consistency-auditor` in parallel.
5. **Chaos** — Run `chaos-injector` only for an unresolved Gate 4 finding where a reproducible fault test would change the merge decision. Do not generate a general chaos backlog.
6. **Operations** — Run `compliance-officer`, `sre`, and `enterprise-readiness` in parallel. A role with no affected surface returns `PASS`.
7. **Resolution** — Merge duplicates, reject inadmissible findings, and decide blockers. Modify files only when the user's request authorizes fixes; otherwise return `BLOCKED` with the smallest required fix.
8. **Final baseline** — If fixes changed the baseline, re-run `docs-writer`, any security role affected by the fix, and only the original owners of still-relevant findings. Produce the ledger and decision.

## Blocking

- Security `CRITICAL` and `HIGH` findings block.
- A docs finding blocks when changed user-visible, operational, API, configuration, permission, audit, compatibility, or upgrade behavior is missing or inaccurate in its required documentation or changelog fragment.
- Other roles use `BLOCKING` only for a demonstrated correctness, safety, compatibility, data, test-validity, or operability defect in scope.
- `SHOULD` requires a concrete in-scope defect but does not block. Fix it when local and low risk; otherwise record a concise rationale or an existing issue. Do not create issues without user authorization.
- Omit style preferences, generic hardening, praise, `LOW`, `INFO`, and `NICE` observations from the ledger.

## Convergence

- Consolidate accepted fixes into one coherent remediation round, then perform one targeted re-review.
- Never re-run a role against an unchanged baseline and unchanged evidence.
- A reviewer may keep a finding open only with evidence that its original consequence remains. It may open a new finding only for a regression introduced by the remediation or newly inspected changed code.
- Do not reopen a finding under a new ID, raise severity, or argue alternate wording without new evidence.
- Resolve reviewer disagreement from tests, code behavior, routed docs, and established neighboring patterns. If those sources do not decide a material product or contract question, stop and ask the user; reviewers do not debate each other.
- Allow at most two remediation rounds. If a blocker remains after the second targeted re-review, stop with `BLOCKED`; do not launch the same loop again.

## Final Output

Lead with findings. For each accepted finding, emit its ID, severity, `file:line`, consequence, evidence, and smallest fix once. Then include:

- validation performed, with command and result;
- one compact role ledger: `PASS`, `FINDINGS`, or `SKIPPED` with counts;
- unresolved blockers and accepted deferrals only;
- `PASS`, `PASS WITH DEFERRED`, or `BLOCKED`.

Keep pass entries to one line. Do not narrate gates, repeat the change summary, reproduce reviewer prose, or list speculative follow-ups.
