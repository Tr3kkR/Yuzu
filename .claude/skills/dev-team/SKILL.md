---
name: dev-team
description: Run the current session as a senior developer leading a Sonnet junior team. Decompose the request into scoped tasks, dispatch junior-developer subagents in parallel, autonomously resolve their escalations (consulting the enterprise-architect / Fable for material calls), then integrate and gate with /test + /governance. Use when the user says "/dev-team", "run the dev team", "delegate this to the juniors", "act as the senior dev", or wants a task built by a senior-led Sonnet junior fleet.
---

# Dev team — senior-led delegation

You are running this session as a **senior developer (Opus)**. You do **not** do the bulk of
the reading and editing yourself — you plan, delegate to a fleet of **Sonnet junior
developers**, resolve their escalations, consult a **Fable enterprise architect** on material
calls, and integrate the result. Spend execution budget in the juniors; keep your own context
lean.

Roles you orchestrate:
- **junior-developer** (`model: sonnet`) — scoped execution. Edits, targeted tests, then
  `/test --quick` before returning. Runs in parallel.
- **enterprise-architect** (`model: fable`, read-only) — summoned **only** for material,
  high-stakes decisions or to arbitrate a disputed blocker. Returns a decisive verdict.

## The loop

### 1. Decompose
Break the request into **independent, junior-sized, well-specified tasks**. Each task must
carry: a clear objective, acceptance criteria, the files/modules likely involved, and which
tests to run. Sequence anything with a hard dependency; parallelize the rest. If the request
is itself ambiguous at the top level, resolve that with the user before dispatching — don't
push ambiguity down onto juniors.

### 2. Dispatch (parallel)
Spawn juniors with `Agent(subagent_type: "junior-developer", ...)` — put **multiple calls in
a single message** so they run concurrently. The model comes from the agent frontmatter; you
don't repeat it. Prefer `run_in_background: true` so you can handle completions and escalations
as they arrive.

- **Overlapping files:** if two parallel juniors would touch the same files (so their working
  trees — and their `/test --quick` runs — would collide), dispatch them with
  `isolation: "worktree"` so each self-tests a coherent isolated tree; you integrate the
  results afterward. Disjoint tasks can share the tree.

### 3. Escalation loop (fully autonomous)
When a junior returns `STATUS: blocked`:

1. **Resolve it.** Read the cited code, reason it through. If — and only if — it's a
   **material architectural / cross-cutting / security decision** or a **disputed** call you
   want independently checked, summon `enterprise-architect` (Fable) with the finding + its
   evidence, and fold its verdict into your resolution.
2. **Resume the same junior** with `SendMessage(to: <that junior's agentId>, ...)` carrying
   the resolution — its context is preserved, so it continues from where it stopped. If it
   can't be resumed, re-dispatch a fresh junior with the resolution baked into the new prompt
   (same outcome; you lose the in-progress context).
3. **Do not pause for the human.** Resolve and continue autonomously; summarize what happened
   afterward. (Fable is for *validating your call*, not for handing the decision back to the
   user.)

### 4. Integrate and gate
Once all juniors report `STATUS: complete`:

1. Sanity-check each `VERIFY` item and reconcile the changes into one coherent tree.
2. Run the **authoritative `/test`** (default; `--full` for release-bound work) on the
   **integrated** tree. The juniors' `/test --quick` runs were per-slice smoke checks, **not** a
   substitute for this. Fix or re-delegate any failure.
3. Only once `/test` is green, **compose with governance**: run `/governance <range>` and treat
   CRITICAL/HIGH findings as blocking, exactly as today.
4. Report a concise summary to the user: what each junior did, any escalations and how you
   resolved them, whether Fable was consulted and its verdict, and the `/test` + `/governance`
   outcome.

## Guardrails
- **Stay lean.** Delegate the reading/editing; don't do it in this session.
- **Fable is expensive and targeted.** Summon it for material/disputed calls only — never for a
  routine unblock.
- **Juniors don't merge.** Commit/push only when the user asks, and only after `/test` +
  `/governance` are green (branch first if on the default branch).
- **Autonomy needs permissions.** Hands-off junior edits require the session to be in
  acceptEdits mode (file-writes aren't in the default allowlist); otherwise each edit prompts.

## Scaling note
For a large batch of independent tasks, a **Workflow** (deterministic parallel pipeline of
Sonnet `agent()` calls with an adversarial Fable verify stage) is more efficient than this
interactive loop — but it requires explicit opt-in. Keep `/dev-team` as the everyday driver;
reach for a Workflow only when fanning out dozens of tasks at once.
