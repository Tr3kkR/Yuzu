# Plugin README standard

Every agent plugin carries its own documentation beside its code: `agents/plugins/<name>/README.md`. A reader must be able to learn how a plugin works, on which operating systems, and what data it calls, sends and receives without opening the source. The same file is the source of a machine-readable manifest the server serves to agentic clients over REST and MCP (rule 10), so its shape is a contract, not a style preference.

The skeleton to copy is `docs/templates/plugin-README.md`. The generator is `tools/plugin-doc-gen/plugin_doc_gen.py`; the capture tool is `tools/plugin-capture`. The gate is `tests/test_plugin_readmes.py` (meson `docs` suite) plus the `plugin-readme-touch-rule` job in `.github/workflows/docs-lint.yml`.

## The standard, in ten rules

1. **One `README.md` per plugin directory** — `agents/plugins/<name>/README.md`. It is the plugin's single human-facing document. `docs/user-manual/agent-plugins.md` is a generated index that links here; it carries no per-plugin prose of its own.
2. **Eight sections, fixed order, fixed headings** (the section contract below). A reader finds the same thing in the same place on every plugin page. All eight are mandatory. A section with nothing to say states that in one line ("Neither action takes parameters") and is never omitted.
3. **Generated fences are never hand-edited.** Everything between `<!-- BEGIN GENERATED: plugin-doc-gen <block> -->` and `<!-- END GENERATED -->` is emitted by the generator from code-adjacent sources: the CI-verified capability-matrix block in `docs/os-capability-matrix.md` (the plugin's declared per-OS legs), `content/definitions/<name>.yaml`, `server/core/src/capability_decls/*.hpp`, and the plugin directory itself. CI byte-diffs the fences. To change one, change its source and regenerate.
4. **Hand-written sections describe the code as it is today, not the intent.** Present tense. "Planned" and "will" appear only under Caveats and known gaps. A claim that cannot be verified by reading the cited source, or by running the capture, does not go in.
5. **Sample output is a real capture on every leg the descriptor declares `supported` or `constrained`**, produced by `plugin-capture` through the agent's real `LocalDispatcher`, stored at `agents/plugins/<name>/docs/samples/<os>.txt` and spliced by the generator. The first line is the stamp: `captured: <os> <os-version> · <host-class> · <date> · <privilege> · leg-hash <hash>`. Host class is `bare-metal`, `vm` or `container`. Unsupported legs show the placeholder row the plugin actually emits. No fabricated rows, ever.
6. **The leg-hash on a capture stamp must match the current legs and column schema.** The generator computes it from the plugin's declared legs (support, rung, mechanism per action per OS) and its definitions' `result.columns` (name, type); the descriptor's fallback prose is excluded so a wording edit never forces a recapture. A mismatch fails the gate until the leg is recaptured. `leg-hash pending` is accepted with a warning for a hand-authored capture that predates regeneration. Plugin versions are not used as the freshness signal because they are bumped inconsistently.
7. **Touch rule.** A pull request that changes `agents/plugins/<name>/src/**` must also change `agents/plugins/<name>/README.md`, or carry a line `docs-unchanged: <section it would have touched> — <reason>` in its body. The override is visible to the reviewer and is named in the review. A plugin that has no README yet is exempt until it gains one; the README-existence ratchet in `tests/test_plugin_readmes.py` governs that count and may only shrink.
8. **Output field tables come from the definition YAML.** `spec.result.columns[]` accepts four optional keys documented in `docs/yaml-dsl-spec.md`: `description`, `values` (the closed vocabulary a column may carry), `example`, and `platforms` (a list drawn from `windows`, `linux`, `darwin`). A missing key renders as `-`. The server ignores keys it does not read.
9. **Regenerate with one command and no build.** `python3 tools/plugin-doc-gen/plugin_doc_gen.py --all` rewrites every README fence, the catalog index, the site navigation fragment and the manifests from the committed sources; `meson compile -C <builddir> docs-regen` wraps it. Only captures need a built plugin, and only on that leg's operating system. The capability-matrix block itself is regenerated on its canonical Linux host, as before.
10. **The README is the source of the machine manifest; the eight headings are the parse contract.** The generator writes `content/plugin-docs/<name>.json` (`manifest_version` 1) from the generated blocks and from the hand-written sections, which it locates by heading. The server embeds those files at build time and serves them as `GET /api/v1/discover/plugin-docs` and the MCP resource `yuzu://plugin-docs`, and joins a per-plugin summary into `discover_plugins`. Renaming a heading, or nesting a section differently, breaks that parse and fails the gate.

## Section contract

| # | Heading | Kind | Source | Content rule |
|---|---|---|---|---|
| 1 | *(title block)* `# <name>` + property table | GENERATED `header` | descriptor identity (name, version, description) from the plugin source; actions and per-OS support from the capability-matrix block; securable, operation, risk, dispatch class and gate from `capability_decls`; definition ids, roles and gather mode from the YAML | What it does · Version · Kind (collector or action; on-demand or gathered) · Platforms (✅ supported · 🟡 constrained or planned · ⛔ unsupported, per OS) · Actions with definition ids · Security · Roles |
| 2 | `## How it works` | HAND | author | 5–10 lines, present tense: what each action reads or changes, in what order, and what it is deliberately not (scope rulings). One mermaid `flowchart LR` from trigger → OS call per leg → rows and status → server store → API. |
| 3 | `## OS capability` | GENERATED `capability` | capability-matrix block | Compact action × OS matrix (support · rung · mechanism), then the declared limits per leg verbatim as a bullet list. |
| 4 | `## Privileges and prerequisites` | HAND | `docs/agent-privilege-model.md` row and the leg source headers | A table with columns `OS · Runs as · Extra grant needed · Measured · If the read is refused`, then one line naming binaries, subprocesses and network use, or "none". |
| 5 | `## Data contract` | GENERATED `inputs` + `outputs`, HAND subsections | YAML `spec.parameters`; YAML `result.columns` with the optional keys; hand tables for `### Result status` and `### Where the data goes` | Subsections in this order: `### Inputs` (fence), `### Outputs` (one hand paragraph on row format and placeholders, then the fence), `### Result status` (hand table `Status · Completeness · Provenance · When`), `### Where the data goes` (hand bullets: instruction result, daily-sync, TAR, DEX, metrics; retention; siblings). |
| 6 | `## Sample output` | GENERATED `samples` | `docs/samples/<os>.txt` files written by `plugin-capture` | One block per OS, stamped. The generator trims each action to 12 rows and says so. |
| 7 | `## Caveats and known gaps` | HAND | author, review threads | At most five numbered items, each a bold lead and one or two sentences. Rejected mechanisms and "do not reintroduce" invariants live here. |
| 8 | `## Source and tests` | GENERATED `source` | plugin directory, definition YAML, capability fragment, tests, privilege-model row, changelog fragments | Paths only, one per line. |

Tone: concise plain English readable at senior-executive level, present tense, no emojis in prose (the ✅ 🟡 ⛔ legend is the one exception, matching the capability matrix), no attribution lines.

## Manifest schema (`content/plugin-docs/<name>.json`, `manifest_version` 1)

| Key | From | Shape |
|---|---|---|
| `manifest_version`, `name`, `version`, `description`, `first_commit` | header | scalars |
| `kind` | capability rows | `{"collector": bool, "mutating": bool, "gathered": bool}` |
| `platforms` | capability-matrix block | `{"windows"\|"linux"\|"macos": "supported"\|"constrained"\|"planned"\|"unsupported"}` (best support across actions) |
| `security` | `capability_decls` | `[{"action","securable","operation","risk_tier","dispatch_class","mutability","execute_gate"}]` |
| `actions` | capability-matrix block + YAML | `[{"action","definition_ids":[…],"legs":{"<os>":{"support","rung","mechanism","fallback"}}}]` |
| `definitions` | YAML | `[{"id","display_name","description","platforms","approval_mode","execute_roles","author_roles","gather"}]` |
| `inputs` | YAML `spec.parameters` | `[{"definition_id","name","type","required","default","description"}]` |
| `outputs` | YAML `result.columns` | `[{"definition_id","columns":[{"name","type","description","values","example","platforms"}]}]` |
| `how_it_works` | README §2 | text with the mermaid fence removed |
| `privileges` | README §4 table | `[{"os","runs_as","grant","measured","if_refused"}]` |
| `result_status` | README §5 table | `[{"status","completeness","provenance","when"}]` |
| `where_the_data_goes` | README §5 bullets | `[string]` |
| `samples` | samples files | `{"<os>": {"stamp": {...}, "actions": [{"action","params","rows":[first 5],"row_count","result_status"}]}}` |
| `caveats` | README §7 | `[string]` |
| `source` | source block | `{"plugin":[…],"definitions":[…],"capability_rows":[…],"tests":[…],"privilege_row":bool,"changelog":[…]}` |
| `readme` | path | `agents/plugins/<name>/README.md` |

## Authoring a README before the generator has run

Fill each fence from its named source exactly as the generator will: the header from the plugin source and the capability fragment; the capability matrix from your own `kActionDescriptors` (support, rung, mechanism; fallback verbatim); inputs and outputs from your definition YAML (add the four optional column keys while you are there); samples from a real run through `LocalDispatcher` on each supported OS, stamped with `leg-hash pending`. The next `--all` run replaces the fences byte-for-byte and fills the hash.
