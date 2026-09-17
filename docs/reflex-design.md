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
                                   # version is NOT authored in yaml_source — see note below
enabled: bool
os_target: [windows|linux|darwin] # filters server-side before push; never rides the wire; the
                                   # agent's own platform string is "darwin", never "macos"
reflexes:
  - reflex_id: string             # unique WITHIN this set (not globally)
    name: string
    enabled: bool
    spark:
      type: file|service|disk|interval|startup|registry   # open set — see "Spark types" above;
                                                            # plist/process are PLANNED (A6/A7)
      params: {..type-specific..}   # schema per reflex_schema_registry.cpp spark_types()
    reactions:                      # sequential, <= 4 deep
      - plugin: string
        action: string
        params: {..}
        gate: always|on_success|on_failure   # first Reaction MUST be "always"; see "Reaction
                                              # success and timeout" below for what on_success means
        timeout_ms: uint32     # default 10_000, max 120_000
        capture_output: bool   # default false; captured output capped at 4 KiB
    cooldown_ms: uint32         # steady_clock-based per-reflex_id debounce
    max_per_hour: uint32        # hourly cap per reflex_id (reuses the existing DexRateLimiter
                                 # primitive, include/yuzu/agent/dex_rate_limiter.hpp)
    fire_on_arm: bool           # default false; see "Reaction success and timeout" below for the
                                 # startup/interval special case
assignment:
  - group_id: string
    disposition: include|exclude   # the closed Baseline-assignment vocabulary (baseline_store.hpp)
```

**`version` is server-bumped, never author-set, and is stripped from (or rejected in) authored
`yaml_source`** on submit — it is not part of the round-tripped, YAML-authoritative content D7
describes; a submitted `yaml_source` that includes a `version` key is either ignored (stripped
before storage) or rejected outright (R4's implementation picks one and is consistent about it),
never silently honored as an author-supplied version number.

Bounds, enforced by the R4 validator (`validate_reflex_set`): **at most 32 reflexes per set**, each
chain **at most 4 Reactions deep**, `reflex_id` unique within the set, `os_target` drawn from the
closed vocabulary above.

**Escalation policy is explicitly deferred** in this rebuild's Reflex v1 — ADR-0021 Decision 4
describes "so many chances over so much time, then act, or don't" as the target shape, but v1 ships
only the cooldown/hourly-cap primitives above. A future escalation-policy field is additive to this
grammar; do not treat its absence here as an oversight.

**`fire_on_arm` on a monostate spark type (`interval`, `startup`, and — with no state to compare —
effectively always-on for `disk`'s threshold check) fires the Reflex once, immediately, the first
time it is armed** (there is no "prior state" for these types to compare against, so "already true
at arm time" is trivially the arm event itself); on an edge-producing type (`service`, `plist`,
`process`) it fires only if the persisted condition is already in the "true" state at arm time,
exactly as described earlier in this document.

## Substitution tokens (closed list)

A Reaction's `params` values may reference the firing Spark event via `{{spark.<fact>}}`, using the
literal `{{...}}` delimiter — matching the convention Reflex content actually implements (the same
one `policy_evaluator.cpp` and shipped content definitions already use), **not** the
`docs/yaml-dsl-spec.md` `${...}` convention documented for other content. A literal `{{` an author
needs verbatim is escaped `\{\{`; an unbalanced or unterminated token is a validation error. The
**only** legal facts, and which spark types can produce them, are listed under "Spark types and
per-type facts" below — `{{spark.key}}`, `{{spark.path}}`/`{{spark.pid}}` (Process only, planned),
`{{spark.service_state}}` (Service only), `{{spark.edge}}` (a closed, per-type enumeration, several
types produce none at all).

`validate_placeholders` (R4) rejects any `{{...}}` token outside this list, and rejects a fact not
published for the Reflex's own spark `type` (e.g. `{{spark.pid}}` on a `file` spark is a validation
error, not a silent empty substitution).

**Substitution is data-only — never shell-composed.** `{{spark.*}}` tokens are **forbidden** in any
parameter that reaches an interpreted context (a `script`/command-body parameter of `script_exec` or
any plugin that composes a shell/interpreter line from its params) and in every parameter of a
**dangerous** Reaction (`execute_gate != None` or `dispatch_class == Destructive`, per the safety
chokepoint) — `validate_reflex`/`validate_placeholders` (R4) refuse the Reflex at compile if a token
appears in either. Where substitution IS legal, the resolved value is passed as a discrete,
argv-style parameter, never interpolated into a composed command string — an attacker-controlled
Spark fact (e.g. a maliciously-named local file whose path becomes `{{spark.path}}`) cannot inject
shell syntax this way.

**Facts are re-validated at execution, against the fired edge, never against compile-time text.** At
fire time the executor re-resolves each referenced fact from the actual `SparkEvent` (e.g.
`{{spark.pid}}` is checked against the process's start time, so a pid recycled between the Spark
firing and the Reaction actually running is detected and refused rather than silently substituted
with an unrelated process's identity). If a referenced fact cannot be resolved at fire time (the
process already exited, the file already vanished), the **whole chain is refused**
(`reflex.aborted{unresolvable_fact}`) — never a partial substitution or an empty string.

**Resolved parameter values are excluded from the outcome journal.** `capture_output` (Reaction
stdout/stderr) is the only per-Reaction content persisted to `reflex_outcomes`; the actual resolved
`{{spark.*}}` substitutions (which may carry a user path, e.g. a resolved `{{spark.path}}`) are
**never** written to the journal or the outcome event — only a basename ever appears in any
persisted record, matching A7's privacy posture and D10's "no SID/username/user path" rule.

## Spark types and per-type facts (open set)

The Reflex grammar's `spark.type` is an **open set published server-side by
`reflex_schema_registry::spark_types()`** — it does **not** mirror
`agents/core/include/yuzu/agent/spark.hpp`'s `SparkType` enum verbatim, and the two must never be
assumed identical; a future type lands in both together (H2/G9 cross-check doctrine), and this
document is updated in the same PR that lands it. As of this document, the set is:

- **Shipped today** (present in `SparkType`, agent-side): `file`, `service`, `disk`, `interval`,
  `startup`, `registry` (Windows-only, gated by `os_target: windows`).
- **Planned, not yet landed** — tracked by the macOS Spark/Reflex programme: `plist` (macOS, lands
  at A6), `process` (ES-backed, lands at A7). A Reflex referencing either is a forward declaration
  the schema registry accepts today only if the underlying slice has actually shipped; until then
  they are absent from the published set, not silently accepted-but-inert.

**`{{spark.key}}` is the Reflex-authored watch key — it is NOT `spark_key()`'s internal wire
encoding.** `spark_key()` (agent-side) returns an opaque `"<type>|<params>"` string used purely for
watcher-table indexing; `{{spark.key}}` is a **per-type target accessor** over the Reflex's own
`spark.params` (e.g. the `path` param on a `file` spark, the `label` param on a `service` spark) —
the human-authored value, never the internal encoding. R5's `resolve_facts` implements the
per-type accessor explicitly.

**`{{spark.edge}}` is a closed, per-type enumeration — most types produce none at all:**

| Spark type | `{{spark.edge}}` values | Notes |
|---|---|---|
| `service` | `started` \| `stopped` \| `paused` | |
| `disk` | `breach` \| `recovery` | a threshold crossing, not a state name |
| `file` | *(none)* | `SparkData` is monostate for this type; no edge fact exists |
| `registry` | *(none)* | monostate |
| `interval` / `startup` | *(none)* | monostate; only `{{spark.key}}` is available |
| `plist` (planned, A6) | `changed` | provisional, confirmed when A6 lands |
| `process` (planned, A7) | `started` \| `exited` | provisional, confirmed when A7 lands |

A Reaction referencing `{{spark.edge}}` on a monostate type is a **validation error** at R4 — no
type-appropriate value exists to substitute, never a silently-empty string.

## Safety chokepoint — `dangerous_reactions_in_spec()`

A **sibling chokepoint** to `dangerous_enforce_in_spec` (`docs/yuzu-guardian-design-v1.1.md` §24) —
**not an extension of it**. `dangerous_enforce_in_spec` (`guardian_rule_spec.cpp`) is an
assertion-type plus a registry-key/service-name allowlist, a distinct mechanism; `dangerous_reactions_in_spec()`
is a separate classifier over `CommandCapabilityRegistry::classify(plugin, action)` (server-owned,
compile-authored; `server/core/src/command_capability.hpp`). Both independently follow the
EXTEND-never-fork doctrine for their own kind of dangerous content; a future unification of the two
mechanisms is an architect-level decision, not implied by either doc. `classify` yields an
`ExecuteGate` (`None|AdminOrApproval|AlwaysApproval`) and a `DispatchClass`
(`ReadOnly|Mutating|Destructive`). A Reaction is **consequential** — and therefore a "dangerous
Reaction" for the purposes of D4's consent gate and D9's approval gate — iff `execute_gate != None`
**or** `dispatch_class == Destructive`. An unclassified or ambiguous `(plugin, action)` pair is a
validation **error**, never a silent "assume safe."

**Reflex Reaction *execution* is agent-LOCAL dispatch, not server-mediated remote dispatch, and is
authorized exactly once — at deploy time — by this chokepoint plus the two gates below.** This
ruling is scoped to **Reaction execution only** — it does **not** describe the `__reflex__/push_sets`
leg that carries a compiled Reflex Set to the agent; see "Wire contract" below, which **is** a
dispatch site. Reaction execution never passes through the server's `classify_and_authorize_dispatch`
/ `DispatchCaller` chokepoint (`agent_registry.hpp`, the "Dispatch-caller approval provenance" routed
concern) — that chokepoint exists to gate an **operator's live remote command**, and there is no live
operator at spark-fire time to gate against. `command_capability.hpp`'s classification is reused for
its taxonomy only; a Reaction firing is explicitly **not** a `DispatchCaller` construction site and
stamps no dispatch approval provenance. Do not conflate the two:

| | Gates | When | Who/what checks |
|---|---|---|---|
| Server-mediated remote dispatch (ordinary commands, **and** the `push_sets` fan-out — see Wire contract) | `classify_and_authorize_dispatch` / `DispatchCaller` | Every dispatch, live | `agent_registry.hpp` |
| Reflex Reaction **execution** (agent-local) | consent gate (D4) + digest-bound approval (D9) | Once, at Reflex Set deploy | `reflex_set_spec.cpp` + `ApprovalManager` (server); `LocalDispatcher` executes unconditionally on the agent once armed |

This mirrors existing prior art: Guardian's own in-thread remediation and the pre-Reflex
`TriggerEngine`-driven local actions (retired by ADR-0021 Decision 5) never re-authorized per fire
either — authorization for agent-local, pre-declared automation lives at content-authoring/deploy
time, not at execution time. This is strictly about *execution*; the server-originated push that
delivers the content is a dispatch like any other, below.

### Reaction success and timeout

A Reaction's **success**, for `gate: on_success`/`on_failure` chain evaluation, is the plugin
action's own **typed result** (its structured status, not a bare process exit code) resolving to a
non-error outcome — matching how every other plugin-dispatch result is already judged elsewhere on
the platform, never a Reflex-specific redefinition. **A timeout counts as failure** — a Reaction
that exceeds `timeout_ms` never gate-admits a subsequent `on_success` step, and the chain's terminal
outcome for that Reaction is `timed_out`, distinct from both `completed` and an in-plugin `failed`.
The consent-gate's stricter "affirmative response TOKEN" rule (see "Consent gate" above) is a
*further* restriction specific to `interaction.*` Reactions gating a *dangerous* Reaction — it is
not a redefinition of "success" for ordinary chain gating in general, which this paragraph defines.

## Two-person approval (D9)

Any Reflex Set deploy whose compiled content contains at least one dangerous Reaction (per the
chokepoint above) requires approval by a principal representing a **distinct human root**, per
ADR-0033 §7's identity-resolution rule — not merely "a different principal string": an editor
approving through their own second API token must not satisfy this gate, and R9's implementation is
responsible for resolving every identity surface (session, API token, MCP principal) back to the
underlying human before comparing. Approval is bound to a **canonical digest**
(`canonical_reflex_digest(spec_json, assignment)`, SHA-256 over key-sorted `spec_json` plus the
resolved assignment/device-set — not a member-ID list) — editing a Reaction's params or the
assignment growing invalidates the approval.

**The approval REQUEST carries the digest the reviewer actually reviewed, and the server rejects on
drift.** If the content changes between review and approve (an editor saves a new version mid-review),
the approval call's digest no longer matches the row's *current* digest, and the server returns a
`409` — approving stale content is not silently accepted as approving the current row. The digest is
also **recomputed and compared at every compile** (`reflex_push_builder.cpp`), fail-closed on
mismatch or absence: see "Generation and undeploy semantics" below for the exact push-time refusal
behavior (a stale/invalid-digest set is never silently downgraded, and a `reflex.set.compile_refused`
critical audit event fires).

**Break-glass is a NEW `ApprovalManager` capability, not an existing one Reflex merely reuses.**
Today's `ApprovalManager` has no emergency single-principal override, no `justification` field, and
no `ApprovalOrigin::kReflexDeploy` value — all three are new work this programme adds to
`ApprovalManager`, requiring their own security review at R9, not a drop-in reuse of an existing
mechanism. (AuthDB's login-lockout break-glass is a different control and does not transfer.) Until
that lands, Reflex deploy has **no** emergency override — a dangerous Reflex Set is blocked on
ordinary two-person approval with no bypass.

RBAC: Reflex gets its **own dedicated securable** (`Reflex`). Per §24's standing invariant, `Push`
stays Guardian-only and is never added to the `crud_ops[]` cross-seed array. **`Execute` is
different: `crud_ops[]` *does* include `Execute`** (it is only `Push` that sits outside it), so
Reflex's `Execute` permission is auto-granted to Administrator + ITServiceOwner by the existing
cross-seed loop like every other securable's `Execute` — this document does not claim `Execute`
is excluded from cross-seeding; it claims only that **`Push` is**, matching every other
non-Guardian securable. (Exact additional role assignments for `Execute` beyond the cross-seed
default are finalized and ratified at R7's own review.)

## Consent gate (D4)

A **preventive compiler gate**, not an authoring convention, and **one rule with no escalation
exception**: a dangerous Reaction (per the safety chokepoint above) is **REFUSED at compile unless
chain-consent or all-server tag-consent holds — independent of any escalation policy.** There is no
weaker "the compiler only rejects `proceed`-on-exhaustion" reading. Escalation policy (deferred, see
the grammar section) can only decide *when*, inside a Reflex whose consent basis already holds, an
already-consented action proceeds — it never widens what a dangerous Reaction may do *without*
consent. The platform gains an operator-declared device classification via the free-form asset tag
key `device_class` (`server` | `workstation`) — **declared, never inferred**; see
`docs/asset-tagging-guide.md` "Recipe: Reflex consent gate." **An unclassified device is
workstation-class — fail-closed.**

`evaluate_consent` (R4) admits a dangerous Reaction under either of:

1. **Chain consent** — an `interaction.*` Reaction gated `on_success` precedes the dangerous
   Reaction in the same chain, **and its result is an affirmative response TOKEN from the
   interaction plugin** (e.g. `response == "ok"`), **never a bare plugin return code**. A prompt
   dismissed, defaulted, or shown with no interactive desktop present (Windows session 0; a headless
   agent) returns `rc == 0` from the plugin but carries **no** affirmative token — that case is a
   **consent FAILURE**, and the chain refuses the dangerous Reaction rather than journaling "consent
   given" for an unattended dismissal.
2. **Tag consent** — every resolved target device satisfies `device_class == "server"`, established
   by a **direct `TagStore::get_tag(agent_id, "device_class")` read** (never the scope-DSL's
   case-insensitive `tag:` atom — a different mechanism with different case-folding semantics; see
   `docs/asset-tagging-guide.md`). The match is **exact-byte** against the literal string `"server"`;
   any other value, any differently-cased value, or an absent tag is `"workstation"`. Device-set
   membership (management-group assignment → device ids) resolves via
   `ManagementGroupStore::get_member_agents_in_subtrees`. ADR-0050's fail-closed
   construction/degrade posture applies: an **unreadable** `TagStore` is an evaluation **error**,
   never treated as `true`.

**Device-set binding, re-tag, and membership drift.** The two-person approval (D9 below) binds its
digest to the **resolved device set at approval time**, not group IDs alone — a management-group
membership growing after approval invalidates it, and the next compile refuses until re-approved
(see D9). Re-tagging a device (`device_class` changes) or a membership change on an
already-deployed, already-armed set triggers a **recompile**: the affected set's consent is
re-evaluated, and if it no longer holds, the set is **disarmed** on the affected device(s) — never
left silently armed under a now-false consent basis.

**`device_class` write authorization.** Because `device_class` is the sole input to this
safety-relevant compiler gate, setting or changing it is **not** a bare `Tag:Write` operation — it
requires **`Reflex:Write` or admin**, and is recorded under a dedicated audit verb
(`reflex.device_class.tag_set`, alongside the `reflex.set.*` verbs below). The existing
service-scoped-token confinement helper `authz::service_scope_may_mutate_tag_key`
(`docs/auth-architecture.md` clause 6) is **extended** to cover `device_class` — a service-scoped
token must clear this check, checked BEFORE the scoped gate and value-blind, exactly like every
other admission-deciding tag key. This is an EXTEND, never a parallel gate.

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

**`push_sets` IS a `DispatchCaller`/system-reserved-dispatch site — it copies the
`__guard__.push_rules` pattern exactly, never the "Reaction execution is not a dispatch" ruling
above (that ruling covers agent-local Reaction firing only).** Concretely: the server builds a
`SystemReservedPush`-class `DispatchCaller{.system = true, .principal_is_admin = true}` (mirroring
`push_rules`'s construction), carries its own `capdecl` row in the capability declarations so the
`consteval` sweep classifies it rather than leaving it an unclassified miss, and goes through
`send_system_reserved` (`dispatch_confined_arms.hpp`) like every other system-originated push. R9
decides explicitly, at implementation time, whether `push_sets` is **quarantine-gated** (subject to
the #881 containment gate like an operator dispatch) or **exempt** (like `push_rules`, which is
itself exempt because a quarantined device must still receive its cached policy) — this document
does not pre-decide that, but the decision must be recorded, not left implicit.

**`__reflex__` control commands stay CLAIMED through `CommandDedupStore`** — the routed
dedup row's "dedup is the SAFE DEFAULT for future reserved names" stands, and `__guard__` remains
the **only** dispatch that bypasses the claim. `push_sets` mints a **per-push unique command id**
(`"__reflex__-<hex>"`, mirroring Guardian's own `__guard__-reconcile-<gen>-<rand>` minting) so a
re-push (retry, reconcile) is dedup'd as a genuinely new command, never replayed as the old one;
`get_status` likewise never reuses a command id across calls.

**Outcome leg — reuses the existing `__guard__`/`event` channel.** Reflex does **not** get its own
outcome proto message. A fired/completed/failed/aborted/suppressed Reflex chain is reported as an
ordinary `GuaranteedStateEvent` (`plugin="__guard__" action="event"`) with the new
`GuaranteedStateEvent.family` field set to `"reflex"` (field 21, proto3 default `""` == `"guardian"`
for backward compatibility with every pre-Reflex agent build, which never sets the field). **`family`
is a CLOSED set at ingest — `{"", "guardian", "reflex"}` — validated at the router
(`guardian_ingest.cpp`); any other value is refused and counted on an `ingest_errors`-style metric,
never silently treated as `"guardian"`.** `rule_id` is **empty for every `family=="reflex"` row** —
it is never repurposed as `<set_id>/<reflex_id>` (that would resurrect exactly the `__observation__`
rule-id-squatting pattern ADR-0021 Decision 6 retires `family` in order to *stop* doing). `set_id`
and `reflex_id` are instead **additive fields on `GuaranteedStateEvent`** (own field numbers,
alongside `family`), carried directly rather than encoded into an overloaded string. `event_type` is
drawn from `reflex.{fired,completed,failed,timed_out,aborted,suppressed_sampled}`, `event_id` is the
correlation id below.

**`severity`/`guard_type`/`guard_category` on a `family=="reflex"` row.** Unlike the
`rule_id="__observation__"` DEX sentinel — whose own doc comment states its severity-enrich is a
no-op specifically because it has no rule to enrich against — a Reflex row is **not** exempted from
these fields; the ingest router populates `severity` from the fired Reaction's own classification
(a dangerous Reaction's `fired`/`failed` outcome carries at least `medium`; a non-dangerous
Reaction's outcome carries `low`), `guard_type` is the literal string `"reflex"` (distinguishing it
in any query/dashboard that groups by `guard_type` from a real Guardian guard type like
`"registry"`/`"scm"`), and `guard_category` is `"event"` (Reflex sparks are event-driven, never a
periodic condition check in the Guardian sense).

**`suppressed_total`'s source is the agent-local counter, not a server-side derivation from sampled
`suppressed_sampled` events.** The two would disagree if `suppressed_total` were instead computed
server-side by counting `suppressed_sampled` events — sampling means most suppressions never emit an
event at all (that is the point of sampling), so a server-derived count would systematically
undercount. `suppressed_total` in `ReflexStatus`/`ReflexSetStatus` is the agent's own running
counter of every suppression, journal-persisted (see "Generation, undeploy, and push semantics"
above), independent of how many of those suppressions were *also* sampled into an emitted event.

**Upgrade ordering is server-before-agent.** The server must accept `family` (and the additive
`set_id`/`reflex_id` fields) before any agent build that sets them is rolled out — an old server
talking to a new agent sees `family=""` never happens by construction (it would see the real value
and, if not yet upgraded, refuse it per the closed-set rule above rather than silently mis-filing it
as Guardian drift); a new server talking to an old agent sees `family=""` correctly resolves to
`"guardian"`. The reverse ordering (agent-before-server) is what the closed-set-at-ingest rule
exists to make safe *if* it ever happens, but it is not the intended rollout order.

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

## Generation, undeploy, and push semantics

**A server-side compile refusal HOLDS the agent's last accepted generation — it is never expressed
as a `full_sync` removal.** `full_sync=true` **replaces the agent's entire active Reflex Set
collection with exactly what the message contains** — so a refused set silently *omitted* from a
`full_sync=true` push is not "held," it is **disarmed fleet-wide** the moment that push lands (this
was the design's own internal contradiction between "generation held" and "full_sync replaces": they
cannot both be true of the same omission). The actual rule: when a compile refusal exists, the
server does **not** advance to a new `full_sync=true` snapshot for the affected agents at all — it
either (a) resends the prior, still-valid `full_sync` snapshot (refused set correctly absent because
it was never in a valid snapshot to begin with) or (b) sends a `full_sync=false` delta that leaves
the refused set's last-known-armed state untouched. R9 picks one of (a)/(b) and states it in its own
implementation notes; this document's job is only to rule out the third, silently-broken option
(treating omission-from-`full_sync` as equivalent to "held").

- **Identical generation is a no-op.** If the agent's already-applied generation matches the
  incoming push's generation, the agent applies nothing and re-arms nothing — an ordinary reconnect
  that re-delivers the same snapshot must not spuriously re-fire `fire_on_arm` Reflexes or reset
  cooldown/hourly-cap state.
- **The agent rejects a push carrying a lower generation than its currently-applied one** (two
  deployers racing, or a reordered redelivery) — a monotonic-generation floor, checked before any
  apply.
- **Undeploy/disable aborts in-flight chains and drains the queue**, reporting
  `reflex.aborted{undeploy}` for every chain that was running or queued at the moment of undeploy —
  "undeploy complete" is never reported while a dangerous Reaction is still executing on the
  agent's worker pool.
- **Per-Reaction completion is recorded, not just the chain's terminal outcome** — a crash mid-chain
  (Reaction 1 of 4 applied, agent restarts) leaves a durable record of *which* Reactions actually
  ran, so a later operator/automation pass has something to reconcile against, rather than a device
  silently wedged half-applied with no record of what happened.
- **Deleting the last (or only) Reflex Set for an agent still pushes an empty `full_sync=true`** —
  there is no such thing as "nothing to push, so nothing is sent"; an empty collection is a real,
  delivered state, so an agent that was offline during the delete does not keep a stale dangerous
  chain armed indefinitely with no server record of the deletion ever reaching it.
- **Cooldown, hourly-cap, and fired/suppressed counters are journal-persisted, not in-memory-only** —
  they survive an agent restart and are **not** reset by re-arm (re-applying the same or a newer
  generation never gives a rate-limited Reflex a fresh budget it would not otherwise have earned).
- **The agent trusts the server (mTLS channel identity) for push authenticity and never independently
  re-verifies the `digest` field** — `digest` is a server-side approval-binding and compile-integrity
  mechanism (D9), not a second authentication layer the agent is expected to check; this is stated
  explicitly so no later slice adds agent-side digest verification believing it closes a gap that
  does not exist on the agent's trust boundary.
- **A pre-Reflex agent build** (one that predates `__reflex__` support entirely) reports "plugin not
  found" for `push_sets`/`get_status`, and — because it never composes the `yuzu.reflex_generation`
  heartbeat tag — the server-side reconcile that would solicit `get_status` never fires for it either.
  Such an agent's Reflex state is therefore reported as a fixed terminal status, **`unsupported`**
  (distinguishable from `--reflex-disable`, which does compose the tag with `yuzu.reflex_disabled=1`,
  and from "offline," which is a connectivity state, not a capability state).

Runtime shape (unchanged claims, restated alongside the semantics above):

- Reflex is a **queued** SparkEngine consumer (ADR-0021 Decision 3) — never inline. Per-Reflex-Set
  concurrency is 1 (serialized chain execution within a set); a worker pool of 2 serves all sets.
  **Reflex maintains its own arm/disarm chokepoint** — analogous to, but a *separate* seam from,
  Guardian's `GuardianEngine::reconcile_rule_locked()` (which is Guardian's own seam, not reusable by
  Reflex) — and its `stop()` is **sticky**: once stopped, Reflex does not re-arm without an explicit
  restart, matching the Spark/Guardian precedent.
- Detached, bounded reaction workers are counted into the agent's hard-exit grace sum — the same sum
  `GuardianEngine::active_io_workers()` feeds today (`guardian_engine.cpp`), summed alongside
  Guardian's own IO/send workers and Reflex's reaction workers under one name; **there is no
  `active_detached_workers()` rename** — a Reaction stuck in a blocking syscall cannot be joined or
  force-cancelled, so it must stay counted, never silently dropped from the sum (the same
  ORPHAN-EXIT CONTRACT `docs/yuzu-guardian-design-v1.1.md` §24 documents for Guardian's send
  executor).
- A chain in progress is journaled with a `chain:` marker; on agent restart, an in-flight marker is
  **aborted, never resumed** (`reflex.aborted{restart}` outcome) — Reflex chains are not
  crash-resumable.
- `event_id` sequence numbers are boot-nonce'd (see above), with the nonce sourced from a **CSPRNG,
  at least 64 bits wide** — a low-entropy (e.g. boot-second-derived) nonce risks an `event_id`
  collision across a crash-loop, which the store's PK-dedup would then silently drop as a
  "redelivery" of an unrelated event.
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

## Outbox sharing and ingest limits

Reflex outcomes and Guardian drift events share the agent's single `__guard__` outbox (they are the
same wire channel, per "Wire contract" above) — this section defines the guards that stop Reflex
from starving Guardian, and Guardian's own enforcement evidence, of that shared, bounded resource.

- **Reflex outcomes get their own lane/quota inside the shared outbox** — a burst of Reflex
  `suppressed_sampled`/`fired` events (up to 32 reflexes × their own `max_per_hour` caps, across
  potentially several event types each) must not be able to fill the outbox and cause Guardian's own
  drift/remediation evidence to back up or drop. The exact quota shape (a reserved slot count, a
  priority tier, or a per-family drop-oldest policy) is an R6/R8 implementation decision; this
  document's job is to require that *some* such guard exists, not to leave the shared outbox
  first-come-first-served across two independent, differently-volumed event sources.
- **Every Reaction's `capture_output` is capped at 4 KiB, but the outcome as a whole is capped to fit
  the ingest clamp.** `GuaranteedStateEvent.detail_json` (which carries the whole `ReflexOutcome` as
  JSON) is subject to the server's existing ~16 KiB ingest clamp; today an over-cap `detail_json` is
  silently **cleared** before the `family` demux even runs. A chain with several captured Reactions
  can exceed 16 KiB (4 × 4 KiB raw, more once JSON-escaped) well before hitting any per-Reaction
  cap. The agent therefore applies a **per-Reaction truncation marker**: if the assembled
  `detail_json` would exceed the ingest clamp, later Reactions' `capture_output` is dropped from the
  payload and the JSON records which ones were truncated (`"truncated": ["reflex_id", ...]`) — the
  event still ships, with an honest record of what is missing, rather than being silently cleared to
  nothing by the server-side clamp.
- **Every fire produces exactly one terminal outcome row, or the loss is signaled.** `reflex_outcomes`
  is claimed as CC7.2 change-detection evidence (see "Observability" below); that claim is only true
  if a fired chain reliably produces exactly one terminal row (`completed`/`failed`/`aborted`). The
  outbox quota above, the truncation marker above, and the journal's own delivery guarantee together
  are what make this hold; if any of them cannot guarantee it in a given implementation, the CC7.2
  claim in "Observability" below must be narrowed or withdrawn in that slice's own PR text — it is
  not carried forward silently.
- **Evidentiary rows have a retention floor**, distinct from the operator-configurable TTL below: an
  operator setting the TTL very short must not be able to make CC7.2 evidence disappear before an
  auditor could plausibly review it. The exact floor value is an R10 decision (see the
  clock-guarded-retention adoption-register row it must record), matching the discipline the Periodic
  Access Reviews "no-prune" precedent (`docs/auth-architecture.md`) sets for evidentiary rows
  generally — this document requires a floor exists, not a specific number.

## Privacy (D10)

- Outcomes record end-user **choices**, not identity: button choice + timestamps + reaction results
  only, **never** free-text input, **never** a SID/username/user path. Device-scoped only. (See
  "Substitution tokens" above: resolved `{{spark.*}}` param values are explicitly excluded from this
  journal — "reaction results" means the Reaction's own outcome, not its resolved input params.)
- `capture_output` is opt-in per Reaction (default `false`), capped at 4 KiB, and a per-device
  outcome drill (including any captured output) is an **access-audited** surface via the existing
  `rest_audit.hpp` chokepoint (`emit_behavioral_audit`) — never a bare read. The drill's audit write
  follows a **named retention class** under `docs/audit_retention_rules.hpp`'s `classify` (assigned
  at R10, alongside a stated fail-closed-vs-set-and-proceed decision for the write itself — see
  `device.live.*`'s fail-closed precedent in the routed device-pages concern as the default lens,
  not an automatic copy).
- Operator-configurable TTL on Reflex outcomes (D10d) — implemented as a clock-guarded retention
  sweep (`docs/clock-guarded-retention.md`; R10 records the adoption-register row), **bounded below
  by the evidentiary retention floor above** — the TTL can be lengthened by the operator, never
  shortened past the floor.
- Fleet-level aggregates are aggregate-first and floor at the shipped `kDexCohortFloor` (an
  aggregate over 1-2 devices is a de facto per-device view); per-device drill stays audited per the
  bullet above.
- Deliberately deferred to the works-council enablement backlog (not omissions): per-category
  collection toggle, an individual-view kill switch, pseudonymization.

## HA — background-job classification and readiness

Reflex introduces four pieces of server background work; each gets an explicit
`BackgroundJobClass` (`server/core/src/background_jobs.hpp` — the live per-surface registry the
Fenced-leader-election routed concern requires every loop to consult, **never a second
"which loops are leader-only" list**):

| Loop | `BackgroundJobClass` | Why |
|---|---|---|
| `reflex_outcomes` TTL sweep (R10) | `FencedLeaderOnly` | A bulk delete — needs the ADR-0012 advisory-locked SHARED clock/dedup rows on Postgres per `docs/clock-guarded-retention.md`'s single-writer rule, exactly like every other clock-guarded reaper. |
| Compile + `push_sets` dispatch (R9) | leader-only | Two replicas independently pushing *different* generations of a dangerous Reflex Set to the same agent is a double-dispatch risk on a destructive surface — the same class of hazard the Fenced-leader-election concern exists to prevent for deployment/quarantine/policy-remediation. |
| `get_status` reconcile-on-heartbeat (R9) | per-replica | Read-only census refresh; safe for every replica to do independently (mirrors `PolicyEvaluator::collect_ready`'s per-replica classification, not its leader-gated `dispatch_due`). |
| Fleet-metric delta tracking (R13) | per-replica, with the double-count rule stated at R13 | Each replica computes its own last-seen delta; R13 must state how a multi-replica deployment avoids double-counting a delta two replicas both observe. |

**Both new Postgres stores join the server's `/readyz` conjunction** — `ReflexSetStore` (R3) and the
`reflex_outcomes` table (R10, inside the same store) are not readiness-invisible; a degraded Reflex
store must surface the same way every other `stores_ok` component does.

**Bounded resource shape, per agent:** a **ceiling on Reflexes-armed-per-agent** (distinct from the
existing ≤ 32-reflexes-per-*set* bound — an agent can have several sets deployed at once), a
**bounded per-agent Reflex job queue**, and a **stated drop policy** (oldest-first, matching the
existing `queue_dropped` counter's semantics) are all required — with a 2-worker pool and Reactions
up to 4 × 120 s each, many simultaneously-armed sets firing near-together can otherwise hold a
worker for minutes with no defined behavior for what happens to the rest of the queue.

## Observability — tags, metrics, audit verbs (reserved vocabulary; R8/R13 implement)

Heartbeat tags (composed by `reflex_heartbeat.hpp`, R8): `yuzu.reflex_running`,
`yuzu.reflex_generation`, `yuzu.reflex_sets_armed` always present; `yuzu.reflex_disabled=1` only
when `--reflex-disable`; sparse per-reflex counters omitted (not zeroed) when unused.

Fleet Prometheus families (R13): gauges
`yuzu_fleet_reflex_{reporting,disabled,sets_armed,unsupported}{os}`; counters
`yuzu_fleet_reflex_{fired,completed,failed,timeouts,queue_dropped,events_missed}_total{os}`
(server-held, last-seen-delta with reset detection — a genuinely new fleet-metric shape this
document introduces, not a precedented one; R13 documents it in
`docs/observability-conventions.md` alongside landing it, since neither of that doc's two existing
fleet-gauge shapes covers a server-held delta counter); server-side
`yuzu_server_reflex_{deploy,compile_refused}_total` pre-seeded labels. **R13 reserves a
`yuzu-reflex` alert group** (`docs/prometheus/yuzu-alerts.yml`) covering `compile_refused` (page —
every dangerous set fleet-wide going refused at once is a silent mass-disarm), `queue_dropped`,
`events_missed`, and `unsupported`-vs-deployed drift — **no alert ships in R0 itself.**

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
