# Yuzu Scope-Walking — Composable Scope from Previous Query Results

**Status:** Design (Phase 1 of TAR dashboard rollout — see `docs/roadmap.md` and `docs/tar-dashboard.md`)
**Audience:** Architects, scope-engine maintainers, DSL implementers, dashboard UI engineers
**Owners:** `architect` agent (cross-cutting), `dsl-engineer` agent (DSL surface), `consistency-auditor` (audit trail)

---

## 1. Why scope walking exists

The IT estate is a **finite-state automaton with a mutating state-table size and mutating per-row state**: machines join and leave, software is installed / patched / removed, users authenticate, files appear and disappear, network posture shifts. An operator's working memory is a few items wide; they cannot hold "the 2,800 Windows boxes that are running Chrome, were last patched before 2026-04-01, have a specific DLL on disk, and currently have an outbound connection to a known-bad ASN" in their head.

The only realistic interaction model for a fleet of 10⁴–10⁶ endpoints is **iterative narrowing** — every query produces a *device set* that becomes the input scope for the next query or action. This document defines that primitive, called a **result set**, and how it propagates through:

- Server-side storage and TTL
- The Scope Engine (`server/core/src/scope_engine.{hpp,cpp}`)
- The REST API (`/api/v1/result-sets/...`)
- The YAML DSL (`scope:` block in `InstructionDefinition`, `InstructionSet`, `Policy`)
- The dashboard UI (sidebar of "your active result sets," chip selector, breadcrumb chain)
- The audit log (every narrowing step is one audit row, so a forensic reconstruction shows the operator's reasoning chain end to end)

The reference user journey is the **Chrome IR walkthrough** in §10.

## 2. Vocabulary

| Term | Meaning |
|---|---|
| **Result set** | A named, TTL-bounded set of device IDs produced by a query, action result, or operator-curated list. The unit of composable scope. Stable identity (`rs_<ulid>`); optional human-readable name. |
| **Source query** | The query (REST request, dashboard form submission, or YAML `InstructionDefinition` invocation) that produced a result set. Persisted verbatim alongside the set so the result is reproducible. |
| **Lineage** | The chain of `(parent_result_set, narrowing_query)` edges leading to a result set. Always rooted at a "ground" set (`__all__`, `group:<name>`, or an inventory query). |
| **Live re-eval** | Re-running a result set's source query against the current estate state. Always produces a *new* result set with a new ID; the original is kept for forensic record. |
| **Pinned result set** | An operator-flagged set whose TTL extends until explicit deletion. Used during incident response so the chain is not garbage-collected mid-incident. |
| **Materialised result set** | A result set whose member device IDs are persisted at evaluation time (vs. evaluated lazily from the source query). The default — see §5 for why. |
| **Scope kind** | The grammar atom in the Scope Engine that selects a device set. Existing kinds: `__all__`, `group:<name>`, attribute selector. New kind: `from_result_set:<id>`. |

## 3. Data model

### 3.1 Server schema (`result_set_store.cpp`, new SQLite database `result_sets.db`)

```sql
CREATE TABLE result_sets (
  id              TEXT PRIMARY KEY,        -- "rs_<ulid>", monotonic, lexically sortable
  name            TEXT,                    -- nullable; operator-supplied alias (unique per owner)
  owner_principal TEXT NOT NULL,           -- session principal; result sets are per-operator
  created_at      INTEGER NOT NULL,        -- epoch seconds
  ttl_at          INTEGER NOT NULL,        -- epoch seconds; row is GC'd when CURRENT_TIMESTAMP > ttl_at AND pinned=0
  pinned          INTEGER NOT NULL DEFAULT 0,
  parent_id       TEXT REFERENCES result_sets(id) ON DELETE SET NULL,  -- lineage edge (nullable for ground sets)
  source_kind     TEXT NOT NULL,           -- 'inventory_query' | 'tar_query' | 'instruction_result' | 'manual_curate'
  source_payload  TEXT NOT NULL,           -- JSON; see §3.2
  device_count    INTEGER NOT NULL,
  CHECK (length(id) >= 5 AND substr(id,1,3) = 'rs_'),
  CHECK (ttl_at >= created_at)
);

CREATE TABLE result_set_members (
  result_set_id TEXT NOT NULL REFERENCES result_sets(id) ON DELETE CASCADE,
  device_id     TEXT NOT NULL,
  PRIMARY KEY (result_set_id, device_id)
);

CREATE INDEX idx_result_sets_owner_ttl ON result_sets(owner_principal, ttl_at);
CREATE INDEX idx_result_sets_parent    ON result_sets(parent_id);
CREATE INDEX idx_result_set_members_dev ON result_set_members(device_id);
```

The schema deliberately mirrors `audit_store` retention discipline: lineage edges and source payloads are immutable once written; `ttl_at` extension is the only post-write mutation. This makes the table a forensic record of the operator's reasoning chain — a `SELECT` walking `parent_id` reconstructs every narrowing step end to end, even after the underlying device state has moved on.

### 3.2 `source_payload` JSON shapes

All shapes carry enough information to **re-evaluate the query against the current estate** (live re-eval) without operator re-input. Examples:

```json
// source_kind = "inventory_query"
{
  "query": "os.platform == \"windows\" AND apps.contains(\"Google Chrome\")",
  "evaluated_at": 1735689600
}

// source_kind = "tar_query"
{
  "sql": "SELECT DISTINCT pid FROM process_live WHERE name = 'chrome.exe'",
  "scope_input_id": "rs_01HXYZ...",
  "evaluated_at": 1735689600,
  "result_columns_used": ["__device_id"]
}

// source_kind = "instruction_result"
{
  "instruction_id": "windows.file.hash_check",
  "params": {"path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
  "scope_input_id": "rs_01HXYZ...",
  "matcher": {"column": "sha256", "op": "in", "value_set_ref": "ioc.chrome.compromised_2026q2"},
  "evaluated_at": 1735689600
}

// source_kind = "manual_curate"
{ "note": "Friday tabletop — Chrome IR drill", "manual_inclusions": ["device-...", "..."] }
```

`evaluated_at` is informational; it does **not** make the membership list stale by itself — re-eval is operator-driven. See §5 for staleness semantics.

### 3.3 TTLs and GC

| Lifecycle stage | TTL behaviour |
|---|---|
| Default creation | `ttl_at = now + 3600` (1 hour) — enough for an active operator session, short enough that abandoned sets do not accumulate |
| Pin | `pinned = 1`, `ttl_at = INT64_MAX`. Audit row written. Pin is reversible — unpinning restores `ttl_at = max(now + 3600, original_ttl_at)` |
| Use as input scope | Touching a set as the scope of a new query or action extends `ttl_at` to `max(ttl_at, now + 3600)` so an operator working a chain does not lose the head of the chain mid-investigation |
| Pin storm guard | Per-operator cap of 50 pinned result sets; further pins return `409 PIN_LIMIT`. Operator must unpin or delete before pinning more |
| GC | Background sweep every 5 minutes deletes rows where `ttl_at < now AND pinned = 0`. Cascades via `ON DELETE CASCADE` to `result_set_members`. Audit row written summarising count of GC'd sets |

Hard maximum cap: **10,000 result sets per operator** (enforced at create time, returns `429 RESULT_SET_QUOTA`). Prevents a runaway script from filling the table.

## 4. Scope Engine extensions

### 4.1 New scope kind: `from_result_set:<id>`

Today's scope expressions are device-attribute predicates evaluated per device by `scope_engine::evaluate(expr, resolver)`. The `__all__` and `group:<name>` selectors short-circuit the per-device walk by returning a precomputed device set.

Add a third short-circuit kind:

```
scope_expr := 'from_result_set:' result_set_id_or_name
            | existing_grammar
```

`from_result_set:rs_01HXYZ...` resolves to the device-ID set materialised in `result_set_members` at evaluation time. `from_result_set:windows-chrome-suspects` resolves the human alias against `(owner_principal, name)` first.

Authorisation: the resolving session must be the owner of the result set **or** hold `Infrastructure:Read` on a target whose role grants `result_set:share` (Phase 2 — initial release is owner-only). Cross-operator sharing without a permission row would defeat the per-operator audit trail.

### 4.2 Composition with attribute predicates

Result-set scope **composes with** attribute predicates via `AND`/`OR`/`NOT`:

```
from_result_set:rs_01HXYZ... AND os.platform == "windows" AND tags CONTAINS "production"
```

Implementation: the scope engine evaluates `from_result_set:` first (set lookup) and then evaluates the remaining predicate against each member device's current attributes. This means **the result set defines the candidate set; the attribute predicate is a real-time refinement against current state** — a critical property for the Chrome IR walkthrough where the original "Windows + Chrome installed" set may have shifted membership by the time the operator pivots to a hash check.

### 4.3 Stale-membership policy

A device that was a member of a result set at creation time but is no longer connected (offline, decommissioned, removed from the management group) is **silently dropped** from the resolved set with a warning surfaced to the dashboard:

```
rs_01HXYZ resolved to 2,798 devices (3 dropped: 2 offline > 24h, 1 decommissioned)
```

`from_result_set:` never errors on stale members — operators iterating an IR chain need progress, not a stop. The audit row records the dropped IDs and reasons so the chain remains forensically complete.

## 5. Materialisation vs. lazy evaluation

The default is **materialisation at create time** — the device IDs are written to `result_set_members` and never re-derived from the source query unless the operator triggers live re-eval. Trade-offs:

| Approach | Pros | Cons | Decision |
|---|---|---|---|
| **Materialise** | Stable, reproducible, audit-friendly, fast resolve | Membership goes stale as estate mutates | Default — operators *want* a stable target during IR |
| **Lazy** | Always fresh | Re-evaluates a possibly-expensive query on every action; results shift mid-chain | Available via `?live=true` query param on resolve |

The dashboard surfaces the materialisation timestamp (`Created 09:42 UTC, 17m ago — Re-eval`) on every result-set chip so the operator knows what they are aiming at. Live re-eval is a one-click action that produces a *new* result set ID; the original stays put.

## 6. REST API

Base path: `/api/v1/result-sets`. All routes require an authenticated session and the principal-owner check (§4.1).

| Method | Path | Body | Returns | Notes |
|---|---|---|---|---|
| `POST` | `/api/v1/result-sets` | `{name?, source_kind, source_payload, device_ids[]}` | `{id, ttl_at, device_count}` | Direct create — operator passes pre-computed members. Used by dashboard for "I have a CSV" import. |
| `POST` | `/api/v1/result-sets/from-inventory-query` | `{name?, query, parent_id?}` | `{id, ttl_at, device_count}` | Server runs the inventory query inside `parent_id`'s scope (or `__all__`) and persists the result. |
| `POST` | `/api/v1/result-sets/from-tar-query` | `{name?, sql, parent_id?}` | `{id, ttl_at, device_count}` | Dispatches the SQL to TAR agents in `parent_id`'s scope; the device-ID set is the union of agents that returned ≥1 row (default) or all agents that responded (`include_empty=true`). |
| `POST` | `/api/v1/result-sets/from-instruction-result` | `{name?, instruction_id, params, matcher, parent_id?}` | `{id, ttl_at, device_count}` | Runs the instruction in `parent_id`'s scope; the device set is filtered by `matcher`. Mirrors the Chrome hash-check step. |
| `GET` | `/api/v1/result-sets` | — | `{result_sets: [...]}` | Pagination by `?cursor=`. Default sort: `created_at DESC`. |
| `GET` | `/api/v1/result-sets/{id}` | — | `{id, name, owner_principal, created_at, ttl_at, pinned, parent_id, source_kind, source_payload, device_count}` | |
| `GET` | `/api/v1/result-sets/{id}/members` | — | `{device_ids: [...]}` | Pagination by `?cursor=`. |
| `GET` | `/api/v1/result-sets/{id}/lineage` | — | `{chain: [{id, name, source_kind, device_count, narrowing}, ...]}` | Walks `parent_id` to root. Used by the dashboard breadcrumb. |
| `POST` | `/api/v1/result-sets/{id}/pin` | — | `{ttl_at, pinned}` | |
| `POST` | `/api/v1/result-sets/{id}/unpin` | — | `{ttl_at, pinned}` | |
| `POST` | `/api/v1/result-sets/{id}/re-eval` | — | `{new_id, device_count_delta}` | Re-runs `source_payload` and creates a new set with `parent_id = original.parent_id` (sibling, not child). |
| `DELETE` | `/api/v1/result-sets/{id}` | — | `204` | Pinned sets must be unpinned first. |

Errors use the `error_codes` taxonomy (`docs/data-architecture.md`): `RESULT_SET_NOT_FOUND`, `RESULT_SET_NOT_OWNER`, `RESULT_SET_QUOTA`, `PIN_LIMIT`, `RESULT_SET_EXPIRED`.

## 7. YAML DSL surface

The DSL must make scope-walking *obvious*, not a footnote. Every place that takes a `scope:` block today gains a new mutually-exclusive form:

```yaml
spec:
  scope:
    fromResultSet: "rs_01HXYZ..."         # by ID
    # OR
    fromResultSet: "windows-chrome-suspects"  # by per-operator alias
```

Coupled with the existing `selector:` form for refinement:

```yaml
spec:
  scope:
    fromResultSet: "windows-chrome-suspects"
    selector:                # refinement — composed with AND
      tags:
        - production
```

Validation rules (enforced at YAML load by `definition_store_*`):

1. `scope` must contain exactly one of: `selector`, `fromResultSet`, `fromResultSet + selector` (combination). `fromResultSet + assignment.managementGroups` is **not** allowed — a result set already has a fixed device set, so layering management-group filtering on top is redundant and confusing; reject with a parse-time error pointing at the YAML line.
2. When `fromResultSet` is present, `assignment.mode` must be `static`. The whole point of a result set is a fixed target — `dynamic` re-evaluation against management groups would defeat it.
3. Result-set references are resolved at instruction *invocation* time, not YAML load time, so an `InstructionDefinition` carrying `fromResultSet:` is valid YAML even if the referenced set has expired by the time it is invoked. Invocation-time resolution failure surfaces as `INSTRUCTION_SCOPE_RESOLUTION_FAILED` with the result-set ID and reason in the audit row.

The DSL spec (`docs/yaml-dsl-spec.md` §9 expression language and §3.2 `scope:` block) gains a new normative subsection covering these rules, with the Chrome IR walkthrough as the anchoring example.

## 8. Dashboard surface

Three dashboard concerns:

### 8.1 Sidebar: active result sets

Persistent left-rail panel showing the current operator's result sets, ranked by `last_used_at` then `created_at DESC`:

```
[★] windows-chrome-suspects     2,798 devices  17m  pinned
[ ] all-windows-fleet           4,011 devices   2h
[ ] tar-chrome-procs           ▶ tar query     8m
```

Each chip has:
- Click → switch the active scope chip in any TAR / inventory / instruction frame
- Right-click → pin, unpin, re-eval, view lineage, delete, rename, copy ID

### 8.2 Chain breadcrumb

Above every query frame, a horizontal breadcrumb of the active result set's lineage:

```
__all__ ─▶ all-windows-fleet ─▶ windows-chrome ─▶ windows-chrome-suspects
                                                              ▲
                                              (active scope — refines next query)
```

Clicking a breadcrumb segment switches the active scope to that ancestor. The breadcrumb is the operator's reasoning chain made visible — the canonical UI mirror of `parent_id` walks in `result_set_lineage`.

### 8.3 Frame integration

Every query frame (TAR SQL, Inventory, Instruction-launch) gains the same "scope chip" header:

```
Scope: [windows-chrome-suspects ▼]   2,798 devices   pinned   17m old   [Re-eval]
```

The chip dropdown lists the operator's active result sets plus the standard scopes (`__all__`, `group:<name>`). Selecting a chip rebinds the frame to the chosen scope. Submitting the frame creates a *new* result set whose `parent_id` is the chip's set.

## 9. Audit and observability

Every state transition writes an `AuditEvent` per `docs/observability-conventions.md`. Action codes:

| Action | Result | Notes |
|---|---|---|
| `result_set.create` | `success` / `failure` | Includes source_kind, parent_id, device_count |
| `result_set.live_reeval` | `success` / `failure` | Includes original_id, new_id, device_count_delta |
| `result_set.pin` / `result_set.unpin` | `success` | |
| `result_set.delete` | `success` | Pinned sets require explicit unpin first; `delete` of an unpinned set is single-action |
| `result_set.gc_sweep` | `success` | Aggregate row, written once per sweep with the count |
| `instruction.scope_resolution_failed` | `failure` | When invocation-time resolve fails. Includes instruction_id, result_set_id, reason |

Prometheus metrics:

| Metric | Type | Labels |
|---|---|---|
| `yuzu_result_sets_total` | counter | `source_kind`, `result` |
| `yuzu_result_sets_alive` | gauge | `pinned` |
| `yuzu_result_set_resolve_seconds` | histogram | `cardinality_bucket` (1, 10, 100, 1k, 10k, 100k+) |
| `yuzu_result_set_gc_total` | counter | |
| `yuzu_result_set_quota_rejected` | counter | |

Enforcement of the per-operator 10,000 cap and the per-operator pin cap fires `result_set_quota_rejected` so SREs can see runaway scripts before they wedge the table.

## 10. Reference walkthrough — Chrome IR

Operator detects a CVE in a specific Chrome version that drops a known-bad DLL on disk. The IOCs are:
- Chrome version `<= 124.0.6367.118`
- Hash of `chrome.exe` matches one of three known-bad SHA256s
- File `C:\Windows\System32\<vendor>.dll` exists and matches one of two known-bad SHA256s

Operator works the chain top-down:

```
Step 1.  Inventory query: os.platform == "windows"
         POST /api/v1/result-sets/from-inventory-query
         → rs_01: "all-windows" (4,011 devices)

Step 2.  Inventory narrowing scoped to rs_01:
         apps.any(name == "Google Chrome" AND version <= "124.0.6367.118")
         POST /api/v1/result-sets/from-inventory-query  (parent_id=rs_01)
         → rs_02: "windows-chrome-vulnerable" (412 devices)

Step 3.  Instruction (tar.process_tree -> file.hash_check) scoped to rs_02:
         hash of "C:\Program Files\Google\Chrome\Application\chrome.exe" IN [bad_hashes]
         POST /api/v1/result-sets/from-instruction-result  (parent_id=rs_02, matcher in [...])
         → rs_03: "windows-chrome-bad-hash" (37 devices)

Step 4.  Instruction (file.exists) scoped to rs_03:
         "C:\Windows\System32\<vendor>.dll" exists AND hash IN [bad_dll_hashes]
         → rs_04: "windows-chrome-compromised" (29 devices)
         Operator pins rs_04. ttl_at = INT64_MAX.

Step 5.  Action: firewall.block_all_except scoped to rs_04
         { allow: ["yuzu-agent:50051"] }
         (audit row: every rs_04 device blocked)

Step 6.  Action: process.kill scoped to rs_04, name="chrome.exe"
Step 7.  Action: software.uninstall scoped to rs_04, package="Google Chrome"
Step 8.  Action: software.install scoped to rs_04, package="Google Chrome", version="125.0.x.x", source=trusted_repo
Step 9.  Action: file.replace scoped to rs_04, path="...<vendor>.dll", source=trusted_blob_ref
Step 10. Action: firewall.unblock_all scoped to rs_04
Step 11. Watch: heightened TAR retention + IOC subscription scoped to rs_04 for 30 days
         (creates a TriggerTemplate-bound policy: rs_04 keeps its pin until the watch ends)
```

Every step's audit row carries `parent_result_set_id` and `result_result_set_id` so a forensic timeline reconstructs the full reasoning chain — *exactly the limited-context-window problem this primitive exists to solve*.

This walkthrough is the reference test for end-to-end correctness. A regression test fixture in `tests/integration/test_chrome_ir_chain.cpp` should drive the chain against a live UAT stack with synthetic agents and assert lineage / audit completeness.

## 11. Roll-out — what ships when

| PR | Deliverable | Doc / code touched |
|---|---|---|
| PR-A | TAR dashboard page shell + retention-paused source list (no scope-walking yet — uses existing scope) | `docs/tar-dashboard.md` PR-A scope. **Starts here** |
| PR-B | `result_set_store.cpp` + `result_sets.db` schema + REST routes (§6) + audit hooks (§9) | Server-side storage and API only |
| PR-C | Scope Engine `from_result_set:` kind (§4) + dashboard scope chip + sidebar + breadcrumb | UI integration of the primitive |
| PR-D | TAR SQL frame consumes / produces result sets via §6 routes | First end-to-end loop in the dashboard |
| PR-E | DSL `fromResultSet:` (§7) + `definition_store` validation + DSL spec amendment | YAML surface |
| PR-F | Reference walkthrough integration test (§10) | Regression net |
| PR-G | Live re-eval, pin storm guards, GC sweep, Prometheus + audit polish | Operational hardening |
| PR-H | Process tree viewer (separate slice — see `docs/tar-dashboard.md` §6) | Builds on PR-D's frame pattern |

PR-A is in scope **for the current session** — it ships the page and the retention list against the existing scope grammar. Everything else is sequenced after.

## 12. Open questions / deferred

- **Cross-operator sharing.** Phase 1 is owner-only. SOC 2 incident response often needs handoff between IR responders; sharing semantics deserve their own design doc once the per-operator baseline ships.
- **Result-set diff over time.** "Show me how `windows-chrome-vulnerable` membership changed in the last 7 days" requires snapshotting the membership at named points; out of scope for v1 but the schema's immutable lineage edges leave room for it.
- **Federation across server instances.** A multi-region Yuzu deployment wants result sets that span sites; deferred until the multi-server data plane lands.
- **Upper bound on lineage depth.** No soft limit today; the dashboard breadcrumb truncates at depth 10 with an ellipsis. Any deeper is operator-pathological.
