# pii_scan

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Sensitive-data (PII) discovery — audits files against a research-backed ruleset of financial, passport, driver's-licence, and national-ID identifiers with real checksum validation. Audit-only, never stores raw matched values. |
| **Version** | 1.0.0 |
| **Kind** | Action · mutating · gathered (security.pii_scan.scan) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `disable_realtime` (definition `security.pii_scan.disable_realtime`) · `enable_realtime` (definition `security.pii_scan.enable_realtime`) · `scan` (definition `security.pii_scan.scan`) |
| **Security** | `scan`: securable `Security` · operation Read · risk Medium · dispatch ReadOnly · approval gate None; `enable_realtime`: securable `Security` · operation Write · risk High · dispatch Mutating · approval gate AdminOrApproval; `disable_realtime`: securable `Security` · operation Write · risk Medium · dispatch Mutating · approval gate AdminOrApproval |
| **Roles** | execute: `scan`: compliance-officer, endpoint-admin, endpoint-operator, security-admin; `enable_realtime`: compliance-officer, endpoint-admin, security-admin; `disable_realtime`: compliance-officer, endpoint-admin, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`scan` walks the operator-supplied `paths` (files or directories), reads each plain-text file under a size cap, and matches its content line-by-line against the embedded ruleset (`content/pii-rules/*.yaml`, ~190 rules across ~45 countries — see `content/pii-rules/00-manifest.yaml`) using RE2. A shape match against a rule with a checksum is validated (Luhn, IBAN mod-97, Verhoeff, ICAO MRZ composite check digits, and ~30 country-specific algorithms); a checksum FAILURE drops the finding entirely rather than downgrading it, since a checksummed identifier that fails its own checksum is very unlikely to be a real instance of that type. A rule with no checksum (or one that can't be computed from the match) falls back to keyword-proximity confidence (MEDIUM with a nearby keyword, LOW without). An optional `jurisdictions` filter (country codes, state-prefixed codes, or region presets) scopes which rules apply; generic identifiers (cards, IBAN, email) always apply. Findings never carry the raw matched value — only a masked form (`mask_value()`: last 4 characters kept, the rest replaced with `*`). `enable_realtime`/`disable_realtime` register or remove a standing agent filesystem trigger (mtime-polling on the watched directory) that re-invokes `scan` when new files appear; this plugin deliberately does NOT attempt on-access (on-read, scan-before-open) interception — that needs a kernel-level hook (Windows minifilter, Linux `fanotify` permission events, macOS Endpoint Security AUTH events), a categorically larger undertaking pushing toward the EDR-style capability set Yuzu is not building.

```mermaid
flowchart LR
  OP[Operator / MCP pii_scan.scan] --> SRV[Server<br/>authz: Security.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[pii_scan.execute]
  EX --> WALK[std::filesystem walk<br/>text-extension allowlist, size cap]
  WALK --> MATCH[RE2 match + checksum validate<br/>pii_checksum.hpp / pii_matcher.hpp]
  MATCH --> MASK[mask_value: last-4-only]
  MASK --> ROWS[severity\|findingConfidence\|category\|ruleId\|filePath\|line\|maskedValue\|complianceTags]
  ROWS --> RS[(ResponseStore)]
  RS --> API[REST /api/responses · MCP]
  TRIG[Agent TriggerEngine<br/>filesystem mtime poll] -.enable_realtime/disable_realtime.-> EX
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `disable_realtime` | ✅ supported · rung 1 · agent_trigger_engine | ✅ supported · rung 1 · agent_trigger_engine | ✅ supported · rung 1 · agent_trigger_engine |
| `enable_realtime` | ✅ supported · rung 1 · agent_trigger_engine (filesystem mtime poll) | ✅ supported · rung 1 · agent_trigger_engine (filesystem mtime poll) | ✅ supported · rung 1 · agent_trigger_engine (filesystem mtime poll) |
| `scan` | ✅ supported · rung 1 · std_filesystem | ✅ supported · rung 1 · std_filesystem | ✅ supported · rung 1 · std_filesystem |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`enable_realtime` / Windows** — catches new/renamed files under the watched directory, not in-place edits to an existing file — see the plugin README's Caveats
- **`enable_realtime` / macOS** — catches new/renamed files under the watched directory, not in-place edits to an existing file — see the plugin README's Caveats
- **`enable_realtime` / Linux** — catches new/renamed files under the watched directory, not in-place edits to an existing file — see the plugin README's Caveats
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | Agent service account. Reads only files the account can already open — no elevation, no impersonation. | None. | Not yet captured on this host — see Caveats. | A per-file permission-denied is skipped silently (`enumerate_files` / `read_file_text` treat an unreadable entry as absent, not an error); the scan continues over the rest of the tree. |
| macOS | Agent daemon. Same no-elevation read model as Windows/Linux. | None. | Not yet captured on this host — see Caveats. | Same silent-skip behaviour as Windows. |
| Linux | Agent daemon. Same no-elevation read model as Windows/macOS. | None. | Not yet captured on this host — see Caveats. | Same silent-skip behaviour as Windows. |

Binaries: none — file access is entirely `std::filesystem`/`std::ifstream`, no subprocess is ever spawned. Network: none beyond the agent's existing gRPC channel to report findings.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `security.pii_scan.disable_realtime` | `watchPath` | string | yes | - | - | The directory previously passed to enable_realtime. |
| `security.pii_scan.enable_realtime` | `watchPath` | string | yes | - | - | Directory to watch. New/renamed files under it trigger an automatic scan. |
| `security.pii_scan.enable_realtime` | `jurisdictions` | string | no | - | - | Same filter semantics as security.pii_scan.scan's `jurisdictions` parameter. |
| `security.pii_scan.scan` | `paths` | string | yes | - | - | Comma-separated list of file or directory paths to scan. |
| `security.pii_scan.scan` | `jurisdictions` | string | no | - | - | Comma-separated filter limiting which countries' rules apply: ISO country codes ("GB","DE"), state-prefixed codes ("US-CA"), or region presets ("EMEA","APAC","AMERICAS"). Empty = no filter, every rule applies. Generic identifiers (credit cards, IBAN, email, ...) always apply regardless of this filter. |
| `security.pii_scan.scan` | `allExtensions` | string | no | - | - | "true" to scan every file found, ignoring the built-in plain-text extension allowlist. |
| `security.pii_scan.scan` | `incremental` | string | no | - | - | "false" to disable the size+mtime fingerprint cache (default: enabled — unchanged files are skipped on repeat scans without re-reading them). |
<!-- END GENERATED -->

### Outputs

Every action writes pipe-delimited rows via `ctx.write_output`: `severity|findingConfidence|category|ruleId|filePath|line|maskedValue|complianceTags`, one row per finding (plus a final `summary` row on `scan` giving files-scanned/findings counts). `findingConfidence` (`HIGH`/`MEDIUM`/`LOW`) is distinct from the rule definition's own `sourceConfidence` (how well-verified the rule itself is — see `content/pii-rules/00-manifest.yaml`); the output never repeats `sourceConfidence` per row, only the per-match `findingConfidence`. `maskedValue` never contains the raw matched text — see `pii_matcher.hpp::mask_value()`.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`security.pii_scan.disable_realtime` — `severity|findingConfidence|category|ruleId|filePath|line|maskedValue|complianceTags`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `severity` | string | - | all | - | - |
| `findingConfidence` | string | - | all | - | - |
| `category` | string | - | all | - | - |
| `ruleId` | string | - | all | - | - |
| `filePath` | string | - | all | - | - |
| `line` | int32 | - | all | - | - |
| `maskedValue` | string | - | all | - | - |
| `complianceTags` | string | - | all | - | - |

**`security.pii_scan.enable_realtime` — `severity|findingConfidence|category|ruleId|filePath|line|maskedValue|complianceTags`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `severity` | string | - | all | - | - |
| `findingConfidence` | string | - | all | - | - |
| `category` | string | - | all | - | - |
| `ruleId` | string | - | all | - | - |
| `filePath` | string | - | all | - | - |
| `line` | int32 | - | all | - | - |
| `maskedValue` | string | - | all | - | - |
| `complianceTags` | string | - | all | - | - |

**`security.pii_scan.scan` — `severity|findingConfidence|category|ruleId|filePath|line|maskedValue|complianceTags`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `severity` | string | - | all | - | - |
| `findingConfidence` | string | - | all | - | - |
| `category` | string | - | all | - | - |
| `ruleId` | string | - | all | - | - |
| `filePath` | string | - | all | - | - |
| `line` | int32 | - | all | - | - |
| `maskedValue` | string | - | all | - | - |
| `complianceTags` | string | - | all | - | - |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `INFO` | Complete | `pii_scan:summary` | The final summary row on a `scan` call — always emitted, even when zero findings were produced. |
| `ERROR` | Partial | `pii_scan:config` | A required parameter (`paths` on `scan`/`scan_path`; `watch_path` on `enable_realtime`/`disable_realtime`) was missing or empty, or an unknown action was dispatched. |

### Where the data goes

- **Instruction result.** Findings land in the `ResponseStore` like any other instruction result, retained per the normal response-retention policy, readable via `GET /api/responses` and MCP.
- **Not consumed by** daily-sync, TAR, DEX, or metrics — this is a one-shot (or trigger-fired) scan action, not a background collector feeding those pipelines.
- **Sensitivity.** A finding's `filePath` and `line` identify where on a specific device a candidate sensitive value lives; `maskedValue` intentionally withholds enough of the underlying value that the row alone does not disclose the PII it found. `ruleId`/`category`/`complianceTags` reveal what *kind* of identifier was found (e.g. a specific country's national-ID scheme), which is itself a mild signal about the device's likely user population — no stronger than what the scan's own `jurisdictions` parameter already told the operator.
- **Siblings:** none yet — this plugin doesn't currently cross-reference `vuln_scan`, `certificates`, or other security-posture plugins' output.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows 11 Pro (10.0.26200) · bare-metal · 2026-09-16 · not measured (capture did not complete) · leg-hash pending

```
== action=scan
[not captured] agent-context: plugin-capture hangs indefinitely on this development host during yuzu_agent_core.dll static initialization (before any plugin code runs) — reproduced against an unrelated, already-shipped plugin (chargen) with the same tool, confirming this is an environment-level issue with plugin-capture/agent-core startup on this host, not a pii_scan defect. The action itself was verified end-to-end via unit tests (tests/unit/test_pii_matcher.cpp's scan_text coverage) and a real MSVC build/link.

== action=enable_realtime
[not captured] agent-context: registers a real agent Trigger Engine trigger — plugin-capture's harness does not provide a live TriggerEngine, so this leg cannot be captured by this tool regardless of the startup-hang issue above.

== action=disable_realtime
[not captured] agent-context: same reason as enable_realtime — needs a live TriggerEngine plugin-capture does not provide.
```

**macOS** — captured: macos not built · bare-metal · 2026-09-16 · not measured (capture did not complete) · leg-hash pending

```
== action=scan
[not captured] agent-context: this plugin was developed and built on Windows only in this environment — no macOS build exists to capture against. See docs/samples/windows.txt for why even the Windows leg's capture did not complete.

== action=enable_realtime
[not captured] agent-context: no macOS build exists in this environment; also needs a live TriggerEngine plugin-capture does not provide regardless of platform.

== action=disable_realtime
[not captured] agent-context: no macOS build exists in this environment; also needs a live TriggerEngine plugin-capture does not provide regardless of platform.
```

**Linux** — captured: linux not built · container · 2026-09-16 · not measured (capture did not complete) · leg-hash pending

```
== action=scan
[not captured] agent-context: this plugin was developed and built on Windows only in this environment — no Linux build exists to capture against. See docs/samples/windows.txt for why even the Windows leg's capture did not complete.

== action=enable_realtime
[not captured] agent-context: no Linux build exists in this environment; also needs a live TriggerEngine plugin-capture does not provide regardless of platform.

== action=disable_realtime
[not captured] agent-context: no Linux build exists in this environment; also needs a live TriggerEngine plugin-capture does not provide regardless of platform.
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Plain-text files only.** Binary document formats (PDF, DOCX, XLSX) need format-specific text extraction this plugin does not do — a file in one of those formats is silently skipped by the extension allowlist (or matched as garbage bytes if `allExtensions=true` is forced, which is not recommended).
2. **On-write realtime catches new files reliably, not in-place edits to existing ones.** `enable_realtime` polls the watched directory's own mtime, which changes on file create/delete/rename but not necessarily when an existing file's content is merely rewritten in place. True on-write detection of in-place edits needs the agent's Trigger Engine extended with native OS directory-change notifications (inotify/ReadDirectoryChangesW/FSEvents) — tracked as follow-up core-agent work, not attempted here.
3. **On-access (on-read) scanning is out of scope entirely, not just unimplemented.** True on-access interception needs a kernel-level hook (Windows minifilter driver, Linux `fanotify` permission events, macOS Endpoint Security AUTH events) — a categorically larger, separately-scoped undertaking that pushes toward the EDR-style capability set Yuzu is deliberately not building.
4. **Sample captures pending.** This README ships without real per-OS `plugin-capture` output (see Sample output above) — the plugin has been verified via its own unit test suite (`tests/unit/test_pii_checksum.cpp`, `tests/unit/test_pii_matcher.cpp`) and a real MSVC build/link/run on Windows, but a `plugin-capture` run on all three OSes is a follow-up.
5. **~30 of the ~46 named checksum algorithms are implemented per their documented specification but not independently vector-tested against a real-world example.** `content/pii-rules/00-manifest.yaml`'s `sourceConfidence` field on each algorithm and rule discloses this per-entry; the shared primitives (Luhn, Verhoeff, IBAN mod-97, the ICAO MRZ check digit) and a handful of country-specific algorithms with an independently-verified worked example ARE vector-tested in `test_pii_checksum.cpp`.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/pii_scan/src/pii_checksum.hpp` · `agents/plugins/pii_scan/src/pii_matcher.hpp` · `agents/plugins/pii_scan/src/pii_rules.hpp` · `agents/plugins/pii_scan/src/pii_scan_collect.hpp` · `agents/plugins/pii_scan/src/pii_scan_plugin.cpp`
- Definitions: `content/definitions/pii_scan.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_pii_scan.hpp`
- Tests: none found by name
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
