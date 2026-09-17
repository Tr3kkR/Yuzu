# Reflex design — agent-local Spark-bound automated response

Status: design-only (R0). Implemented incrementally by slices R1-R14 of the Spark/Reflex/DEX
programme; each slice cites the specific paragraph below it implements. Authoritative source:
`docs/adr/0021-spark-reflex-architecture.md` (Decisions 2, 4, 5, 7, 9, 10 and their Amendments),
`docs/spark-stage2-guardian-consumer-design.md`, `docs/yuzu-guardian-design-v1.1.md` §24. This
document is itself the canonical home for the fixed points below — later slices cite it rather than
re-deriving these rules; if a later slice's PR text disagrees with this file, this file wins unless
amended here first, in the same spirit as `docs/instruction-file-standard.md` "one canonical home."

## Terminology

(Reused verbatim from ADR-0021; restated here because this file, not the ADR, is what later slices
read line-by-line.)

- **Spark** — a use-case-agnostic detection trigger (type + params). Consumers receive events,
  never watcher instances. Reflex is one of three *sibling* Spark consumers (Guardian, DEX, Reflex)
  — never a specialization of another (ADR-0021 Decision 2).
- **Reflex** — an agent-local binding from a Spark to one or more Reactions, executed on the device
  the moment the Spark fires, with or without server connectivity.
- **Reaction** — one plugin invocation (plugin, action, params) within a Reflex's chain; runs
  sequentially, gated on the prior Reaction's result.
- **Reflex Set** — the deployable unit: a named, versioned, assigned collection of Reflexes.
  Individual Reflexes never deploy alone — exactly the Baseline grammar.

## YAML-authoritative Reflex Set grammar

`yaml_source` is authoritative (D7) — the server never re-derives content from `spec_json` alone;
`spec_json` is a compiled, canonical (key-sorted) projection used for the digest and the agent push.

```yaml
name: string                      # unique per docs/postgres-store-playbook.md UNIQUE constraint
version: uint64                   # server-bumped on every update; not author-set
enabled: bool
os_target: [windows|linux|macos]  # filters server-side before push; never rides the wire
reflexes:
  - reflex_id: string             # unique WITHIN this set (not globally)
    name: string
    enabled: bool
    spark:
      type: file|service|plist|process|disk|interval|startup
      params: {..type-specific..}   # schema per reflex_schema_registry.cpp spark_types()
    reactions:                      # sequential, <= 4 deep
      - plugin: string
        action: string
        params: {..}
        gate: always|on_success|on_failure   # first Reaction MUST be "always"
        timeout_ms: uint32     # default 10_000, max 120_000
        capture_output: bool   # default false; captured output capped at 4 KiB
    cooldown_ms: uint32         # steady_clock-based per-reflex_id debounce
    max_per_hour: uint32        # hourly cap per reflex_id (HourlyRateLimiter)
    fire_on_arm: bool           # default false — an already-true condition fires on arm only if set
assignment:
  - group_id: string
    disposition: string         # same vocabulary as Baseline assignment
```

Bounds, enforced by the R4 validator (`validate_reflex_set`): **at most 32 reflexes per set**, each
chain **at most 4 Reactions deep**, `reflex_id` unique within the set, `os_target` drawn from the
closed vocabulary above.

**Escalation policy is explicitly deferred** in this rebuild's Reflex v1 — ADR-0021 Decision 4
describes "so many chances over so much time, then act, or don't" as the target shape, but v1 ships
only the cooldown/hourly-cap primitives above. A future escalation-policy field is additive to this
grammar; do not treat its absence here as an oversight.

## Substitution tokens (closed list)

A Reaction's `params` values may reference the firing Spark event via `{{spark.<fact>}}`. The
**only** legal facts are:

- `{{spark.key}}` — the armed Spark's watch key (e.g. a file path or service label as originally
  authored)
- `{{spark.path}}` — resolved at fire time, **Process spark type only** (the full executable path;
  never persisted — only the basename travels in the event itself, per A7's privacy posture)
- `{{spark.pid}}` — Process spark type only
- `{{spark.service_state}}` — Service spark type only
- `{{spark.edge}}` — the transition that fired (e.g. `started`/`exited`, `changed`/`deleted`)

`validate_placeholders` (R4) rejects any `{{...}}` token outside this list, and rejects a fact not
published for the Reflex's own spark `type` by `reflex_schema_registry::facts_for(spark_type)` (e.g.
`{{spark.pid}}` on a `file` spark is a validation error, not a silent empty substitution).

## Safety chokepoint — `dangerous_reactions_in_spec()`

Extends the existing `dangerous_*_in_spec` doctrine (`docs/yuzu-guardian-design-v1.1.md` §24) —
**never a parallel gate.** A Reaction is classified via the existing
`CommandCapabilityRegistry::classify(plugin, action)` (server-owned, compile-authored;
`server/core/src/command_capability.hpp`), which yields an `ExecuteGate`
(`None|AdminOrApproval|AlwaysApproval`) and a `DispatchClass` (`ReadOnly|Mutating|Destructive`). A
Reaction is **consequential** — and therefore a "dangerous Reaction" for the purposes of D4's
consent gate and D9's approval gate — iff `execute_gate != None` **or** `dispatch_class ==
Destructive`. An unclassified or ambiguous `(plugin, action)` pair is a validation **error**, never
a silent "assume safe."

**Reflex Reaction execution is agent-LOCAL dispatch, not server-mediated remote dispatch, and is
authorized exactly once — at deploy time — by this chokepoint plus the two gates below.** It never
passes through the server's `classify_and_authorize_dispatch` / `DispatchCaller` chokepoint
(`agent_registry.hpp`, the "Dispatch-caller approval provenance" routed concern) — that chokepoint
exists to gate an **operator's live remote command**, and there is no live operator at spark-fire
time to gate against. `command_capability.hpp`'s classification is reused for its taxonomy only;
Reflex deploy is explicitly **not** a `DispatchCaller` construction site and stamps no dispatch
approval provenance (R9 records this as a one-line comment at `dispatch_caller.hpp`, since that
field's doc comment is a closed, diffed list of stamping sites). Do not conflate the two gates:

| | Gates | When | Who/what checks |
|---|---|---|---|
| Server-mediated remote dispatch (ordinary commands) | `classify_and_authorize_dispatch` / `DispatchCaller` | Every dispatch, live | `agent_registry.hpp` |
| Reflex Reaction (agent-local) | consent gate (D4) + digest-bound approval (D9) | Once, at Reflex Set deploy | `reflex_set_spec.cpp` + `ApprovalManager` (server); `LocalDispatcher` executes unconditionally on the agent once armed |

This mirrors existing prior art: Guardian's own in-thread remediation and the pre-Reflex
`TriggerEngine`-driven local actions (retired by ADR-0021 Decision 5) never re-authorized per fire
either — authorization for agent-local, pre-declared automation lives at content-authoring/deploy
time, not at execution time.

## Two-person approval (D9)

Any Reflex Set deploy whose compiled content contains at least one dangerous Reaction (per the
chokepoint above) requires approval by a **different principal**, evaluated across every identity
surface (session, API token, MCP principal), and distinct from **both** the last content editor and
the deployer. Approval is bound to a **canonical digest**
(`canonical_reflex_digest(spec_json, assignment)`, SHA-256 over key-sorted `spec_json` plus the
assignment list — not a member-ID list) — editing a Reaction's params or widening the assignment
invalidates the approval. The digest is **recomputed and compared at every compile**
(`reflex_push_builder.cpp`), fail-closed on mismatch or absence: a stale/invalid-digest set is
**skipped** from the push (never silently downgraded), the set's generation is held, and a
`reflex.set.compile_refused` critical audit event fires. Break-glass (single-principal emergency
override, mandatory justification, `critical`-severity audit) applies identically to the unified
`ApprovalManager` flow, using `ApprovalOrigin::kReflexDeploy`; a break-glass approval still binds
the same digest, so any subsequent edit re-requires approval.

RBAC: Reflex gets its **own dedicated securable** (`Reflex`), with an explicit `Execute` permission
gating deploy. Per §24's standing invariant, `Push` stays Guardian-only and is never added to the
`crud_ops[]` cross-seed array — Reflex's grants are explicit, separately seeded. (Exact role
assignments for `Execute` are finalized and ratified at R7's own review; this document fixes only
that the permission exists and is never folded into a cross-seeded op.)

## Consent gate (D4)

A **preventive compiler gate**, not an authoring convention. The platform gains an
operator-declared device classification via the free-form asset tag key `device_class` (`server` |
`workstation`) — **declared, never inferred**; see `docs/asset-tagging-guide.md` "Recipe: Reflex
consent gate." The compiler **rejects** `proceed`-on-exhaustion escalation on a dangerous Reaction
whose resolved target scope can include a workstation-class device. **An unclassified device is
workstation-class — fail-closed.**

`evaluate_consent` (R4) admits a dangerous Reaction under either of:

1. **Chain consent** — an `interaction.*` Reaction gated `on_success` precedes the dangerous
   Reaction in the same chain (the end user already made an explicit choice earlier in the same
   fire).
2. **Tag consent** — every resolved target device satisfies `tag:device_class == "server"`
   (`TagStore` read; ADR-0050's fail-closed construction/degrade posture applies: an **unreadable**
   tag store is an evaluation **error**, never treated as `true`).

Server-scoped variants (Reflex Sets whose entire assignment resolves to `device_class == "server"`
devices only) may use `proceed`-on-exhaustion escalation; a mixed or workstation-inclusive
assignment may not, regardless of chain consent, because chain consent is per-fire and
proceed-on-exhaustion is specifically the no-user-present case.

## Wire contract

Two independent legs, both opaque `payload` bytes on the existing `CommandRequest`/
`CommandResponse` bidi stream — **no gateway regen for either leg** (matches the existing
`__guard__` precedent: no `guaranteed_state_pb`/`reflex_pb` module exists on the Erlang side).

**Control leg — reserved plugin name `__reflex__`** (R1 arms both interception halves, mirroring
`__guard__`: load-time in `plugin_loader.cpp`'s `kReservedPluginNames`, dispatch-time in
`agent.cpp` before the plugin scan):

| Direction | plugin | action | payload |
|---|---|---|---|
| Server → Agent | `__reflex__` | `push_sets` | `ReflexSetPush` |
| Server → Agent | `__reflex__` | `get_status` | (none) |
| Agent → Server | `__reflex__` | `status` | `ReflexSetStatus` |

**Outcome leg — reuses the existing `__guard__`/`event` channel.** Reflex does **not** get its own
outcome proto message. A fired/completed/failed/aborted/suppressed Reflex chain is reported as an
ordinary `GuaranteedStateEvent` (`plugin="__guard__" action="event"`) with the new
`GuaranteedStateEvent.family` field set to `"reflex"` (field 21, proto3 default `""` == `"guardian"`
for backward compatibility with every pre-Reflex agent build, which never sets the field). The
`ReflexOutcome` struct (R6) is mapped into that message's existing `detail_json` field as JSON
(`rule_id` repurposed as `<set_id>/<reflex_id>`, `event_type` drawn from
`reflex.{fired,completed,failed,aborted,suppressed_sampled}`, `event_id` the correlation id below).
This keeps Reflex on the **same single unsolicited-event channel and the same single server-side
ingest router chokepoint** that ADR-0021 Decision 6 established — only the event *store* is
Reflex-specific (`reflex_outcomes`, R3/R10), never the router.

**Correlation ids — two distinct, deliberately different-looking namespaces, do not confuse them:**

- **Command id** for the `__reflex__`/`push_sets` command: `"__reflex__-<hex>"` (double
  underscore, matches the reserved-plugin-name prefix — mirrors the `__guard__-` convention).
- **Event id** for a Reflex outcome: `"reflex-<agent>-<nonce>-<seq>"` (single leading token, no
  double underscore) — boot-nonce'd so a restart cannot collide sequence numbers with a
  not-yet-acked prior journal entry.

Both prefixes are recognized by the executions-ladder skip rule below; they are not interchangeable
and a future reader must not assume one implies the other.

## Agent runtime contract

- Reflex is a **queued** SparkEngine consumer (ADR-0021 Decision 3) — never inline. Per-Reflex-Set
  concurrency is 1 (serialized chain execution within a set); a worker pool of 2 serves all sets.
- Detached, bounded reaction workers are counted into the agent's hard-exit grace sum
  (`active_detached_workers()`, alongside Guardian's own IO/send workers) — a Reaction stuck in a
  blocking syscall cannot be joined or force-cancelled, so it must stay counted, never silently
  dropped from the sum (the same ORPHAN-EXIT CONTRACT `docs/yuzu-guardian-design-v1.1.md` §24
  documents for Guardian's send executor).
- A chain in progress is journaled with a `chain:` marker; on agent restart, an in-flight marker is
  **aborted, never resumed** (`reflex.aborted{restart}` outcome) — Reflex chains are not
  crash-resumable.
- `event_id` sequence numbers are boot-nonce'd (see above).
- `full_sync=true` on `ReflexSetPush` **replaces** the agent's entire active Reflex Set collection;
  `full_sync=false` is a delta merge. A per-set compile/digest failure on the server holds that
  set's generation (it is simply omitted from the push) rather than partially applying a stale set.
- Any Reflex maintenance work sharing a joined thread (journal paging, etc.) must carry its own
  `steady_clock` cadence — time-paced, never wake-paced (§24's journal-maintenance invariant applies
  verbatim; R8's `ReflexOutcomeJournal::maintenance_tick` implements this).

## Executions-history ladder stance

Reflex fire-and-react events are **agent-local automation, not operator-initiated dispatch** — they
get **no executions-tracker row and no SSE bus publish**. `notify_exec_tracker` (agent-side) and the
server's ingest path both skip any id carrying the `__reflex__-` (command) or `reflex-` (event)
prefix, exactly as the existing `polchk-*`/`preflight-*`/`deployment-*` id families are skipped
today (see `docs/executions-history-ladder.md`). **Any future SSE tile surfacing Reflex activity
needs its own `classify_reflex_event_for_scope` twin** (mirroring the existing per-consumer
confined-projection sanitizer pattern) and its own pin test — it must not be bolted onto the
existing bus consumer set without one.

## Privacy (D10)

- Outcomes record end-user **choices**, not identity: button choice + timestamps + reaction results
  only, **never** free-text input, **never** a SID/username/user path. Device-scoped only.
- `capture_output` is opt-in per Reaction (default `false`), capped at 4 KiB, and a per-device
  outcome drill (including any captured output) is an **access-audited** surface via the existing
  `rest_audit.hpp` chokepoint (`emit_behavioral_audit`) — never a bare read.
- Operator-configurable TTL on Reflex outcomes (D10d) — implemented as a clock-guarded retention
  sweep (`docs/clock-guarded-retention.md`; R10 records the adoption-register row).
- Fleet-level aggregates are aggregate-first and floor at the shipped `kDexCohortFloor` (an
  aggregate over 1-2 devices is a de facto per-device view); per-device drill stays audited per the
  bullet above.
- Deliberately deferred to the works-council enablement backlog (not omissions): per-category
  collection toggle, an individual-view kill switch, pseudonymization.

## Observability — tags, metrics, audit verbs (reserved vocabulary; R8/R13 implement)

Heartbeat tags (composed by `reflex_heartbeat.hpp`, R8): `yuzu.reflex_running`,
`yuzu.reflex_generation`, `yuzu.reflex_sets_armed` always present; `yuzu.reflex_disabled=1` only
when `--reflex-disable`; sparse per-reflex counters omitted (not zeroed) when unused.

Fleet Prometheus families (R13): gauges
`yuzu_fleet_reflex_{reporting,disabled,sets_armed,unsupported}{os}`; counters
`yuzu_fleet_reflex_{fired,completed,failed,timeouts,queue_dropped,events_missed}_total{os}`
(server-held, last-seen-delta with reset detection, mirroring `spark_fleet_tags.hpp`'s pinned-pair
pattern); server-side `yuzu_server_reflex_{deploy,compile_refused}_total` pre-seeded labels.

Audit verbs (R7/R9/R10): `reflex.set.{create,update,delete,deploy,undeploy,approval_required,
compile_refused}`; `reflex.outcome.view` (per-device drill, ADR-0017 `authorize_list_read`
confinement); `reflex.fragment.access_denied` (dashboard, service-scoped-token confinement, R12).

SOC 2 rows (R13): CC6/CC8 two-person deploy control; CC7.2 change-detection evidence via the
outcome journal.

## Pending routed-concern row (NOT added to `.claude/routed-concerns.md` — see reason below)

`.claude/routed-concerns.md` measures **37,810 of its 40,000-character budget** as of this writing
(`tests/test_issue_docs.py`) — 2,190 characters of headroom. The row text below runs 2,242
characters, so it does not fit even on its own (let alone leaving headroom for the next concern),
and it is independently over the "pay-as-you-go" ~500-character self-funding threshold in
`docs/instruction-file-standard.md` (a PR that ships no code has nothing else in that file to trim
to self-fund it). This is a known, called-out possibility in this slice's own brief. The row text
below is the exact, ready-to-paste content for whoever lands the trim PR that frees headroom in
that file (or folds this into an existing row) — copy this one so the two files
never independently drift:

> | Reflex — agent-local Spark→Reaction automated response (ADR-0021 D2/D4/D5/D7/D9/D10). Reflex is
> a SIBLING consumer of Spark, never a Guardian specialization (D2) — YAML-authoritative content
> (D7), deployed only as a Reflex Set (D4), gated on the dedicated `Reflex:Execute` securable (§24's
> `Push`-is-Guardian-only invariant is unaffected — Reflex never touches `crud_ops[]`/`Push`).
> CATASTROPHIC: (1) the **consent gate** — a consequential Reaction (dangerous per
> `dangerous_reactions_in_spec()`, fed by `CommandCapabilityRegistry::classify`) may deploy
> `proceed`-on-exhaustion escalation only when every resolved target device satisfies
> `tag:device_class == "server"` (TagStore, ADR-0050 fail-closed) OR an `interaction.*` Reaction
> gated `on_success` precedes it in the chain — an UNCLASSIFIED device is workstation-class and
> REFUSED, and an unreadable TagStore is an error, never a silent `true`; (2) **digest-bound
> two-person approval** (D9) — `ApprovalOrigin::kReflexDeploy`, a different principal from both the
> last content editor and the deployer, recomputed and compared at every compile, fail-closed on
> mismatch; (3) Reflex reaction execution is **agent-LOCAL dispatch** (`LocalDispatcher`), authorized
> ONCE at deploy time by (1)+(2) above — it never passes through the server's
> `classify_and_authorize_dispatch`/`DispatchCaller` chokepoint, which governs operator-initiated
> REMOTE dispatch only; do not conflate the two. (4) Outcomes live in a Reflex-only table
> (`reflex_outcomes`), demuxed at the shared Guardian ingest router by
> `GuaranteedStateEvent.family=="reflex"` — Guardian's blast-radius/alert-router observers MUST NOT
> fire on a `family=="reflex"` row. (5) No executions-ladder tracker row / SSE bus entry for
> `reflex-*`/`__reflex__-*` ids (agent-local, not an operator dispatch) — a future SSE surface needs
> its own `classify_reflex_event_for_scope` twin. | `docs/reflex-design.md` +
> `docs/adr/0021-spark-reflex-architecture.md` (Amendments) | `security-guardian` + `cpp-safety` +
> `docs-writer` on `reflex_*.{hpp,cpp}`, `agents/core/include/yuzu/agent/reflex_engine.hpp`,
> `proto/yuzu/reflex/v1/reflex.proto`, the `__reflex__` intercept in `agent.cpp`, or
> `GuaranteedStateEvent.family` handling in `guardian_ingest.cpp` |

## Cross-references (for the slices that implement this document)

R1 (`__reflex__` reserved name), R2 (Spark-consumer hoists), R3 (`ReflexSetStore` schema), R4 (YAML
validator + safety/consent chokepoints), R5 (Spark runtime), R6 (executor + outcome mapping), R7
(REST + RBAC), R8 (agent wiring), R9 (deploy/approval/push), R10 (ingest/outcomes/TTL), R11 (MCP
twins), R12 (dashboard), R13 (observability), R14 (macOS proof).
