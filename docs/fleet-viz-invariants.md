# Fleet Visualization — Standing Invariants

The 3D fleet visualizer is built as an 11-PR ladder on `feat/viz-engine`. Each
PR layers on the previous one, and each round of governance hardening adds
invariants that successor PRs must respect. This doc collects those
invariants so they outlive any single PR description.

Triggers for this doc: any change touching
`viz_routes.{hpp,cpp}` / `fleet_topology_store.{hpp,cpp}` /
`viz_page_ui.cpp` / `static/yuzu-viz.js` / `--viz-disable` /
`Config::viz_disable`. Loaded by `security-guardian` + `docs-writer` during
governance.

## REST and routing surface

- **Endpoints.** `/api/v1/viz/fleet/topology` (JSON snapshot) +
  `/fragments/...` (HTMX fragments).
- **Page route.** `/viz/fleet`, auth-gated. Responses set
  `Cache-Control: no-cache, no-store, must-revalidate` to close the
  stale-page-vs-fresh-asset skew window — page shell and module bundle must
  reload together.
- **Route ordering.** No future `/viz/<param>` regex may be registered
  *before* `/viz/fleet` in the route table — the more-specific literal must
  win the match (arch-S1).

## Kill switch and DoS cap

- **Kill switch.** `--viz-disable` flag or `YUZU_VIZ_DISABLE` env var. Tier
  check precedes RBAC permission check: a disabled tier returns 503 before
  any auth/permission evaluation.
- **`machines_max` DoS cap (M-1).** Default 5000, hard ceiling 100000.
  Snapshot fetch refuses to materialize beyond the cap.

## Audit

- **Actions.** `viz.fleet_topology` (read) and
  `viz.fleet_topology.invalidate` (cache bust).
- **Envelope.** `target_type = FleetTopology`. Results are one of `success` /
  `denied` / `failure`.

## Fragment / JSON escape

- **Fragment `</script>` escape.** Any JSON embedded in an HTML fragment
  flows through `escape_json_for_script` before insertion. Inline
  `<script type="application/json">` blocks must use this helper.
- **Fetcher executions-tracker opt-out.** The viz fetcher does not emit
  executions-history rows; rationale lives at the fetcher call site.

## Metrics

- **Store-internal gauges.** `yuzu_viz_refill_*` are gauge-as-snapshot — the
  store writes the value at refill time, not a counter.
- **Fetch duration histogram (PR 6 / OBS-2).**
  `yuzu_viz_topology_fetch_duration_seconds` is wired via
  `set_fetch_duration_observer`. **Fires once per refill including on
  fetcher exception** — observer must be invoked from a `finally`-equivalent
  path so a thrown fetcher still contributes a sample.

## Page-shell invariants (`viz_page_ui.cpp`)

- **Importmap ordering (UP-1, HTML spec).** `<script type="importmap">` must
  be parsed *before* any `<script type="module">` that imports a bare
  specifier. Reversing the order produces a silent module-not-found at
  runtime.
- **WebGL context loss handlers (UP-3).** Both `webglcontextlost` and
  `webglcontextrestored` must be wired; lost-context handler must call
  `event.preventDefault()` to allow restoration.
- **WASD listener guards (sec-M1).** Keyboard handlers must early-return when
  the focused target is `INPUT`, `TEXTAREA`, `SELECT`, or has
  `contentEditable === 'true'`. Without this, typing in a search box steers
  the camera.
- **Importmap support detector (UP-16).**
  `HTMLScriptElement.supports('importmap')` must be probed *before* the
  importmap tag is parsed. Browsers without importmap support need the
  fallback path.

## Renderer invariants — PR 6 (`static/yuzu-viz.js`)

The renderer bundle is built via `embed_js.py` rather than a hand-written
TU — it crossed the MSVC 16,380-byte raw-string literal limit at PR 6.
Standing rules:

- **Stable per-agent layout.** Use **FNV-1a 32-bit** (`hash32`) for
  deterministic agent → grid-slot assignment. Random or wall-clock-seeded
  layout breaks operator muscle memory across refreshes.
- **Cube material.** `MeshPhysicalMaterial({transparent: true, opacity:
  0.18})`. The historical `0.08` value made internal process dots
  effectively invisible against a dark background.
- **Hostname labels.** Sprite via `CanvasTexture`. No DOM-overlay labels —
  they don't survive frustum culling and they break the WebGL hit-test.
- **Tooltip raycasting.** `Raycaster` on `mousemove`. Tooltip output uses
  `escapeHtml` on every agent-controlled field written via `innerHTML`
  (sec-M1).
- **Camera reset guard (UP-7).** `Number.isFinite(camera.position.{x,y,z})`
  check in the render loop; on failure reset to the default position. NaN
  positions can leak in from bad orbit-control input and corrupt every
  subsequent frame.
- **HTTP status handling (UP-17).** `fetchAndRender` must surface 401, 403,
  and 503 explicitly — not collapse them to a generic error toast.
- **Schema gate.** Reject the response unless `schema === 'fleet_topology.v1'`
  before any render call.

## Edge invariants — PR 8 (intra-cube localhost edges)

- **`ConnectionEdge.dst_pid`** is the resolved peer pid on the SAME machine for
  `EdgeScope::Local` connections only. Default zero; non-zero only after the
  pairing pass.
- **Reciprocal-pair resolution.** `build_snapshot()` pairs each Local-scope
  edge with its reciprocal half by exact 4-tuple swap: edge C with
  `src_addr=X, src_port=P_X, dst_addr=Y, dst_port=P_Y` pairs with C' where
  `(C'.src_addr, C'.src_port) == (Y, P_Y)` AND
  `(C'.dst_addr, C'.dst_port) == (X, P_X)`. Sets `C.dst_pid = C'.src_pid`.
- **Drop unmatched.** Any `EdgeScope::Local` edge whose `dst_pid` is still 0
  after the pairing pass is dropped from the snapshot
  (`std::erase_if(m.connections, ...)`). Rationale: the renderer cannot draw a
  line into nothing, and the wire payload stays consistent with the
  rendered scene.
- **Non-Local edges untouched.** The pairing+drop pass discriminates on
  `scope != EdgeScope::Local`. `InternalFleet` and `External` edges keep
  `dst_pid == 0` and survive untouched.
- **Schema minor bump.** `schema_minor` is **2** (was 1 in PR 2–7).
  Renderers must ignore unknown minor versions; the JSON addition is
  `dst_pid` on Local edges and is emitted only when non-zero (mirrors the
  `dst_agent_id`-when-non-empty pattern from PR 2).
- **Renderer line construction.** For each Local edge with both `src_pid`
  and `dst_pid` set, build `THREE.LineSegments(BufferGeometry from points,
  LineBasicMaterial({color: 0xffffff, transparent: true, opacity: 0.3}))`
  and add to the per-cube `processGroup`. Per-cube parenting reuses
  `clearFleet`'s `traverse(disposeNode)` walk for free disposal — no
  separate edge index needed.
- **`Number.isFinite` guards.** Both `src_pid` and `dst_pid` go through
  `Number.isFinite` before being used as Map keys, so a malformed agent
  payload (string pid, NaN, undefined) cannot crash the render loop or
  leak undefined-keyed Map entries.

## Process-layer invariants — PR 7

- **Per-machine `processGroup`** is attached as a *child of each cube*
  (architect NICE-1). Sibling-group alternatives were considered and
  rejected; per-cube children give PR 8 per-cube edges and PR 11 per-cube
  LOD for free, and reuse `clearFleet`'s `traverse(disposeNode)` walk for
  free disposal.
- **`CATEGORY_PALETTE`** is six colours matching the agent's
  `category_to_string()` enum exactly:

  | Category | Hex |
  |---|---|
  | `system` | `#6e7681` |
  | `browser` | `#58a6ff` |
  | `database` | `#d29922` |
  | `web` | `#56d364` |
  | `runtime` | `#bc8cff` |
  | `other` | `#8b949e` |

- **Interior layout.** Deterministic `hash32(pid|ppid)`-mod-bucket placement
  with `hash32('j|pid')` jitter, inside `cubeSize * 0.78` interior fraction
  (leaves a ~11% margin on each side).
- **Process dot geometry.** Low-poly `SphereGeometry(0.22, 6, 4)` +
  `MeshBasicMaterial`, per-instance for clean disposal. **PR 11 polish moves
  to `InstancedMesh`** — defer until then to keep PR 7's diff focused.
- **Raycast.** Flat `processMeshes[]` index alongside `cubeMeshes[]`.
  **Process raycast must precede cube raycast** in `onMouseMove`. Process
  dots live inside the translucent cubes; without this ordering the cube's
  outer face always wins by distance and operators can never hover the
  dots.
- **Process tooltip.** Surfaces `pid / name / user / category`. `escapeHtml`
  on every interpolated string field; `Number(...) | 0` to coerce `pid` to
  an integer before formatting (sec-M1 mirror of renderer rule).
- **Soft cap.** 1000 process dots per cube; bundle size cap <80 KB.

## Cross-references

- REST API surface: `docs/user-manual/rest-api.md` § Fleet Visualization
- Audit log rows: `docs/user-manual/audit-log.md` (viz rows)
- Metrics: `docs/user-manual/metrics.md` § Fleet visualization metrics
- Renderer source: `static/yuzu-viz.js` (codegen via `embed_js.py`); a
  shorter copy of these invariants is kept at the head of the file so
  edits don't drift from the rules.
- Page shell source: `viz_page_ui.cpp` (header comment block).
- REST source: `viz_routes.cpp` (header comment block).
