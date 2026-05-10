// Yuzu fleet visualization renderer (PR 5 + PR 6 + PR 7 of feat/viz-engine
// ladder).
//
// Scene built by PR 5: scene + perspective camera + ambient + directional
// light + ground grid + axes helper, with OrbitControls drag-rotate /
// wheel-zoom and a custom WASD pan listener (OrbitControls' `enablePan`
// is off so WASD owns translation).
//
// Cube layer added by PR 6: fetches `data-yuzu-viz-url`, lays N machines
// out on a `ceil(sqrt(N))` grid with positions seeded by a deterministic
// FNV-1a hash of `agent_id` (so the same fleet renders identically across
// reloads), draws each as a translucent `MeshPhysicalMaterial` cube
// coloured by OS family, and labels them with a Sprite carrying the
// hostname. Hover surfaces a fixed-position tooltip via a Raycaster.
//
// Process layer added by PR 7: each cube owns a child `THREE.Group`
// (`yuzu-processes`) of small `SphereGeometry` dots, one per process,
// laid out on an `hash(pid|ppid)`-mod-bucket interior 3D grid (deterministic
// across reloads, jittered to break stripes) and coloured from the
// six-category palette (system / browser / database / web / runtime /
// other). The per-machine subgroup is the deliberate architecture pick
// over a single sibling processGroup (gov R6 architect NICE-1) — it
// makes per-cube localhost edges (PR 8) trivial, gives clearFleet's
// existing `traverse(disposeNode)` walk free dispose for the new
// subtree, and keeps per-machine LOD culling for PR 11 a one-liner.
// Hover raycaster checks process meshes BEFORE cube meshes so an
// operator hovering a dot through the translucent cube face sees the
// process tooltip (otherwise the cube's outer face always wins by
// distance and PR 7's whole point — drilling into processes — would
// be visually unreachable).
//
// Mount contract: mount() runs idempotently on DOMContentLoaded and on
// `htmx:afterSettle`. It locates `[data-yuzu-viz-url]` (set in viz_page_ui.cpp
// on `#viz-root`) and bails early if already mounted (canvas survival
// invariant — HTMX swaps of `#viz-overlay-panel` must not blow away the
// WebGLRenderer's GPU context).
//
// PR 8/9 add intra- and inter-machine edges; PR 10 adds the
// vulnerability overlay; PR 11 polishes (LOD, instancing, scheduler).
//
// Load contract:
//   <script type="importmap"> maps "three" -> /static/three.module.min.js
//                       and    "three/addons/controls/OrbitControls.js"
//                              -> /static/three-orbit-controls.js
//   <script type="module" src="/static/yuzu-viz.js"> runs this file.
//
// The bundle is embedded into the server binary at build time via
// embed_js.py. Source byte-identical to the served asset.

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

// Dev-console handle. The `__internal` namespace is intentional --
// the namespace itself signals that nothing here is a stable API.
// Future PRs (interior process nodes, edges, vuln overlay) will
// reshape these fields freely; if you're a userscript or third-party
// integration, do NOT depend on `window.YuzuViz.__internal.*`. Tests
// and the developer console use this surface; everything else should
// go through the REST endpoints. (gov R6 architect SHOULD-3.)
window.YuzuViz = window.YuzuViz || {};
window.YuzuViz.__internal = window.YuzuViz.__internal || {};

const STEP = 1.5;             // WASD pan step in world units per frame at full speed
const FOV = 50;               // perspective FOV (degrees)
const NEAR = 0.1;
const FAR = 2000;
const GRID_SIZE = 200;
const GRID_DIVISIONS = 40;

function showError(rootEl, msg) {
  const e = rootEl && rootEl.querySelector('#viz-error');
  if (!e) return;
  e.textContent = msg;
  e.classList.add('shown');
}

// PR 6: per-OS cube colour palette. Keys match the lowercase substring we
// expect in `MachineNode.os` from fleet_topology.v1; default covers
// agents whose os field is empty or unknown. Hex chosen for visual
// contrast on the dark default background; opacity is set on the
// material, not the colour, so colour stays vivid through transparency.
const OS_PALETTE = {
  linux:   '#f0c674',  // tango-yellow
  darwin:  '#a0a0a0',  // mac silver
  macos:   '#a0a0a0',
  windows: '#5294e2',  // win10 blue
  default: '#666666'
};
function pickOsColor(osName) {
  if (!osName) return OS_PALETTE.default;
  const k = String(osName).toLowerCase();
  if (k.indexOf('linux') >= 0) return OS_PALETTE.linux;
  if (k.indexOf('darwin') >= 0 || k.indexOf('mac') >= 0) return OS_PALETTE.darwin;
  if (k.indexOf('windows') >= 0 || k.indexOf('win32') >= 0) return OS_PALETTE.windows;
  return OS_PALETTE.default;
}

// PR 7: per-category process-node palette. Keys exactly match the lowercase
// strings emitted by category_to_string() in process_category.hpp; any
// string not in the table falls through to `other`. Hex chosen for visual
// contrast against the cube's translucent shell on the dark canvas. Pinned
// in test_static_js_bundle.cpp — the palette is a UX contract; changing
// a colour is deliberate, not incidental.
const CATEGORY_PALETTE = {
  system:   '#6e7681',
  browser:  '#58a6ff',
  database: '#d29922',
  web:      '#56d364',
  runtime:  '#bc8cff',
  other:    '#8b949e'
};
function pickCategoryColor(category) {
  if (!category) return CATEGORY_PALETTE.other;
  const k = String(category).toLowerCase();
  return CATEGORY_PALETTE[k] || CATEGORY_PALETTE.other;
}

// FNV-1a 32-bit hash of a string. Used to derive a stable per-agent
// position so the same fleet renders in the same grid cells across
// reloads. Math.imul matches FNV's 32-bit unsigned multiply semantics
// in V8/JSC; the final `>>> 0` re-coerces to unsigned. Pure function;
// no globals.
function hash32(str) {
  let h = 0x811c9dc5;
  const s = String(str || '');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

// PR 6: lay N machines out on a `ceil(sqrt(N))` grid centred on the
// origin. Sort by hash32(agent_id) so the order is stable across renders
// even when the fetched array order changes (server JSON is unspecified
// on row order). Returns [{machine, x, y, z}].
const CUBE_SIZE = 8;
const CUBE_SPACING = 18;
function layoutMachines(machines) {
  if (!machines || machines.length === 0) return [];
  const sorted = machines.slice().sort(function (a, b) {
    const ha = hash32(a && a.agent_id);
    const hb = hash32(b && b.agent_id);
    if (ha !== hb) return ha - hb;
    const ka = (a && a.agent_id) || '';
    const kb = (b && b.agent_id) || '';
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const N = sorted.length;
  const cols = Math.max(1, Math.ceil(Math.sqrt(N)));
  const rows = Math.ceil(N / cols);
  const out = [];
  for (let i = 0; i < N; i++) {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const x = (col - (cols - 1) / 2) * CUBE_SPACING;
    const z = (row - (rows - 1) / 2) * CUBE_SPACING;
    const y = CUBE_SIZE / 2;
    // gov R5 UP-7: defensive — Math operations on a large/strange agent
    // count could in principle yield non-finite intermediates. WebGL
    // crashes on NaN positions, so skip silently rather than render a
    // broken scene.
    if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(z)) continue;
    out.push({machine: sorted[i], x: x, y: y, z: z});
  }
  return out;
}

function buildCube(machine) {
  const color = new THREE.Color(pickOsColor(machine.os));
  const geom = new THREE.BoxGeometry(CUBE_SIZE, CUBE_SIZE, CUBE_SIZE);
  const mat = new THREE.MeshPhysicalMaterial({
    color: color,
    transparent: true,
    // Stale agents (didn't respond to fetch_snapshot before deadline)
    // get a much fainter cube so they read as "unknown" without
    // disappearing entirely.
    opacity: machine && machine.stale ? 0.08 : 0.18,
    roughness: 0.4,
    metalness: 0.0,
    clearcoat: 0.1,
    side: THREE.DoubleSide
  });
  const cube = new THREE.Mesh(geom, mat);
  // Outline: a wireframe overlay reads better than just the translucent
  // shell against a dark grid. Subtle, same colour as the cube.
  const wire = new THREE.LineSegments(
    new THREE.EdgesGeometry(geom),
    new THREE.LineBasicMaterial({color: color, transparent: true, opacity: 0.55}));
  cube.add(wire);
  // Stash the machine on userData so the raycaster can read it back
  // without a parallel id->object map.
  cube.userData.yuzuMachine = machine;
  return cube;
}

// PR 7: lay N processes out on a 3D bucket grid INSIDE a cube's local
// coordinate frame. Returns [{process, x, y, z}] in cube-local units, so
// the caller attaches the dots to a Group that's a child of the cube and
// the dots orbit/translate with the cube unchanged.
//
// Bucket count is `ceil(cbrt(max(N*1.5, 8)))` — the *1.5 slack reduces
// hash-collision rates so processes with similar pids don't pile up; the
// floor of 8 ensures even tiny machines (a handful of system procs) get
// a roughly volumetric scatter rather than collapsing onto one cell.
//
// Layout key: `hash32(pid|ppid)` is the bucket index; a secondary
// `hash32('j|pid')` provides per-process sub-cell jitter in [-0.35, 0.35]
// of cell size, breaking the grid stripe pattern while preserving the
// "same fleet renders identically across reloads" contract.
//
// Interior fraction is 0.78 — keeps every dot well inside the cube faces
// (which are at ±CUBE_SIZE/2) so process dots never visually escape the
// cube on rotation. Combined with PROCESS_DOT_RADIUS the worst-case dot
// surface stays inside ~95% of the cube edge.
const PROCESS_DOT_RADIUS = 0.22;
const PROCESS_INTERIOR_FRACTION = 0.78;
function placeProcessesInCube(processes, cubeSize) {
  if (!processes || processes.length === 0) return [];
  const N = processes.length;
  // gov: process count from the server is bounded by tar.fleet_snapshot
  // truncation (per machine), so N stays in low thousands worst-case.
  const buckets = Math.max(2, Math.ceil(Math.cbrt(Math.max(N * 1.5, 8))));
  const span = cubeSize * PROCESS_INTERIOR_FRACTION;
  const cellSize = span / buckets;
  const halfSpan = span / 2;
  const out = [];
  for (let i = 0; i < N; i++) {
    const p = processes[i] || {};
    const pidStr = String(p.pid != null ? p.pid : '0');
    const ppidStr = String(p.ppid != null ? p.ppid : '0');
    const h = hash32(pidStr + '|' + ppidStr);
    const bx = h % buckets;
    const by = Math.floor(h / buckets) % buckets;
    const bz = Math.floor(h / (buckets * buckets)) % buckets;
    const jh = hash32('j|' + pidStr);
    // Each byte of the secondary hash gives a uniform-ish ±0.35 jitter.
    const jx = ((jh & 0xff) / 255 - 0.5) * 0.7;
    const jy = (((jh >> 8) & 0xff) / 255 - 0.5) * 0.7;
    const jz = (((jh >> 16) & 0xff) / 255 - 0.5) * 0.7;
    const x = (bx + 0.5 + jx) * cellSize - halfSpan;
    const y = (by + 0.5 + jy) * cellSize - halfSpan;
    const z = (bz + 0.5 + jz) * cellSize - halfSpan;
    // gov R5 UP-7 mirror: NaN/Infinity from Math.cbrt or hash arithmetic
    // would crash WebGL on render. Skip silently rather than emit a
    // malformed mesh position.
    if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(z)) continue;
    out.push({process: p, x: x, y: y, z: z});
  }
  return out;
}

// PR 7: build a small sphere mesh for one process. Per-process geometry +
// material (matches the cube's per-instance pattern in buildCube) so
// clearFleet's traverse(disposeNode) walk releases everything cleanly
// without a shared-resource skip flag. Low-poly sphere (6×4 segments)
// because each dot is ~0.22 units against a 8-unit cube — the polygon
// silhouette difference vs higher segment counts is invisible at any
// reasonable camera distance, and the triangle count savings matter
// once a 100-machine fleet × 50 processes/machine = 5k spheres land on
// the GPU. PR 11 polish moves to InstancedMesh.
//
// MeshBasicMaterial (not Phong/PBR) because lighting on a 0.22-unit
// dot is invisible and the basic shader is materially cheaper per draw
// call. The colour comes straight from the category palette.
function buildProcessNode(process) {
  const color = new THREE.Color(pickCategoryColor(process && process.category));
  const geom = new THREE.SphereGeometry(PROCESS_DOT_RADIUS, 6, 4);
  const mat = new THREE.MeshBasicMaterial({color: color});
  const mesh = new THREE.Mesh(geom, mat);
  mesh.userData.yuzuProcess = process;
  return mesh;
}

function buildHostnameLabel(hostname) {
  // Sprite-based label — always faces the camera, no text-vs-cube
  // perspective fight. Render to a small canvas, upload as a texture.
  const canvas = document.createElement('canvas');
  canvas.width = 256;
  canvas.height = 64;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = 'rgba(0,0,0,0.55)';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.font = 'bold 28px sans-serif';
  ctx.fillStyle = '#ffffff';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  let label = String(hostname || '(unknown)');
  if (label.length > 24) label = label.slice(0, 23) + '…';
  ctx.fillText(label, canvas.width / 2, canvas.height / 2);
  const tex = new THREE.CanvasTexture(canvas);
  tex.minFilter = THREE.LinearFilter;
  // gov R6 perf-F4: hostname canvas is rendered at fixed 256x64 and never
  // sampled below its native resolution (Sprite is screen-space scaled,
  // not perspective-shrunk). Disable mipmap generation -- saves ~30% GPU
  // VRAM per sprite (no mip-chain build) and skips the synchronous GPU
  // pipeline pause on each upload during addMachines() at high N.
  tex.generateMipmaps = false;
  tex.needsUpdate = true;
  const mat = new THREE.SpriteMaterial({map: tex, transparent: true, depthTest: false});
  const sprite = new THREE.Sprite(mat);
  sprite.scale.set(8, 2, 1);
  return sprite;
}

function buildScene() {
  const scene = new THREE.Scene();
  // Background pulled from CSS bg token at render time so theme switches
  // without a JS rebuild. fallback matches the dark default.
  const bgVar = getComputedStyle(document.documentElement)
    .getPropertyValue('--bg').trim() || '#0d1117';
  scene.background = new THREE.Color(bgVar);

  // Ambient + directional light gives flat translucent cubes (PR 6+) a
  // subtle face-shading hint without overwhelming the colour palette.
  scene.add(new THREE.AmbientLight(0xffffff, 0.55));
  const dir = new THREE.DirectionalLight(0xffffff, 0.65);
  dir.position.set(50, 80, 30);
  scene.add(dir);

  // Ground grid -- subtle, dim, gives the camera spatial reference. Pulls
  // its colours from CSS tokens like the rest of the design system.
  const gridFg = getComputedStyle(document.documentElement)
    .getPropertyValue('--mds-color-theme-text-tertiary').trim() || '#6e7681';
  const grid = new THREE.GridHelper(GRID_SIZE, GRID_DIVISIONS,
                                    new THREE.Color(gridFg),
                                    new THREE.Color(gridFg));
  grid.material.opacity = 0.25;
  grid.material.transparent = true;
  grid.position.y = 0;
  scene.add(grid);

  // Axes helper -- 5-unit length so it's visible at startup but doesn't
  // dominate the view once cubes land. PR 11 may make this toggleable.
  const axes = new THREE.AxesHelper(5);
  axes.material.depthTest = false;
  axes.renderOrder = 1;
  scene.add(axes);

  return scene;
}

function mount() {
  const root = document.querySelector('[data-yuzu-viz-url]');
  if (!root) return;                          // not on /viz/fleet
  if (root.dataset.yuzuVizMounted === '1')    // already mounted -- HTMX swap
    return;                                   // re-fired afterSettle
  root.dataset.yuzuVizMounted = '1';

  const canvas = root.querySelector('#viz-canvas');
  if (!canvas) {
    showError(root, 'viz-canvas element missing');
    return;
  }

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true,
      // gov R4 DEP-2: 'high-performance' would force the dGPU on hybrid
      // laptops, costing battery for an empty grid + a few hundred
      // translucent cubes. 'default' lets the browser pick (typically
      // the iGPU on battery, dGPU on AC) which is plenty for our scene.
      // Revisit if PR 11 LOD/instancing measurements show iGPU choking.
      powerPreference: 'default'
    });
  } catch (e) {
    showError(root, 'WebGL not available in this browser: ' + (e && e.message));
    return;
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setSize(canvas.clientWidth, canvas.clientHeight, false);

  // gov R4 UP-3 / CHAOS-2: WebGL context can be lost at runtime (GPU
  // driver crash, OS GPU reset, sleep/wake, dGPU<->iGPU switch). Without
  // a handler the rAF loop keeps calling renderer.render() on the dead
  // context, spamming console errors and showing a frozen frame with no
  // operator-visible signal. We surface the loss via #viz-error and stop
  // the rAF loop; on restored we hide the error and let the operator
  // refresh manually (Three.js does not auto-recover scene state, so a
  // full reload is the cleanest path).
  let _contextLost = false;
  canvas.addEventListener('webglcontextlost', (e) => {
    e.preventDefault();
    _contextLost = true;
    showError(root, 'WebGL context lost (GPU reset or driver issue). ' +
                    'Reload the page to recover.');
  }, false);
  canvas.addEventListener('webglcontextrestored', () => {
    _contextLost = false;
    const err = root.querySelector('#viz-error');
    if (err) err.classList.remove('shown');
  }, false);

  const scene = buildScene();

  const camera = new THREE.PerspectiveCamera(
    FOV, canvas.clientWidth / Math.max(canvas.clientHeight, 1), NEAR, FAR);
  camera.position.set(35, 30, 35);
  camera.lookAt(0, 0, 0);

  // OrbitControls drives drag-to-rotate + wheel-zoom; pan is disabled so
  // the WASD listener owns translation in screen space.
  const controls = new OrbitControls(camera, canvas);
  controls.enablePan = false;
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.minDistance = 4;
  controls.maxDistance = 400;
  // Allow looking from above and below but not flipping past the poles.
  controls.minPolarAngle = 0.05;
  controls.maxPolarAngle = Math.PI - 0.05;

  // ── WASD pan ────────────────────────────────────────────────────────────
  // Pan vector accumulates each frame from the keys-held set; rAF loop
  // applies it in camera screen space. This avoids the per-keydown jitter
  // of binding pan directly to the keydown event.
  //
  // gov R4 sec-M1 / UP-6: skip when a focused element is text-editable so
  // typing W/A/S/D into a future overlay-panel <input> / <textarea> /
  // contenteditable region doesn't have its keystrokes silently eaten.
  const heldKeys = new Set();
  function isEditableTarget(t) {
    if (!t) return false;
    const tag = t.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
    return t.isContentEditable === true;
  }
  function onKey(e, down) {
    if (isEditableTarget(e.target)) return;
    const k = e.key && e.key.toLowerCase();
    if (k !== 'w' && k !== 'a' && k !== 's' && k !== 'd') return;
    if (down) heldKeys.add(k); else heldKeys.delete(k);
    e.preventDefault();
  }
  window.addEventListener('keydown', (e) => onKey(e, true));
  window.addEventListener('keyup',   (e) => onKey(e, false));

  // Reusable temporaries so the rAF loop doesn't allocate per frame.
  // gov R4 perf-S2 / HP-1: `_offset` was previously allocated fresh each
  // frame WASD held; hoist alongside the other temporaries. Removed the
  // dead `_quat` declaration that was never referenced.
  const _right  = new THREE.Vector3();
  const _up     = new THREE.Vector3(0, 1, 0);
  const _mvDir  = new THREE.Vector3();
  const _offset = new THREE.Vector3();

  function applyWasdPan() {
    if (heldKeys.size === 0) return;
    // Camera-basis right vector: up x forward.
    camera.getWorldDirection(_mvDir).normalize();
    _right.crossVectors(_up, _mvDir).normalize();
    // Build a world-space pan from the keys: W=+screenY, S=-screenY,
    // A=-screenX, D=+screenX. We translate BOTH camera position AND
    // controls.target so OrbitControls' rotate-around-target stays sane.
    let dx = 0, dy = 0;
    if (heldKeys.has('w')) dy += STEP;
    if (heldKeys.has('s')) dy -= STEP;
    if (heldKeys.has('a')) dx -= STEP;
    if (heldKeys.has('d')) dx += STEP;
    if (dx === 0 && dy === 0) return;
    // dx maps along camera right, dy along camera up. Reset and reuse
    // the hoisted _offset rather than allocating per frame.
    _offset.set(0, 0, 0)
           .addScaledVector(_right, dx)
           .addScaledVector(_up,    dy);
    camera.position.add(_offset);
    controls.target.add(_offset);
  }

  // ── Resize handler ──────────────────────────────────────────────────────
  // ResizeObserver on the canvas keeps the renderer + camera aspect in
  // sync as the window or surrounding chrome changes. Cheaper than
  // listening to window.resize and querying clientWidth.
  const ro = new ResizeObserver(() => {
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    if (w === 0 || h === 0) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  });
  ro.observe(canvas);

  // ── PR 6: cube + label group ──────────────────────────────────────────
  // Single THREE.Group hosts every machine cube + sprite label. fetchAndRender
  // empties + repopulates the group on success; on failure the group stays
  // empty and #viz-error surfaces a message so the operator never sees a
  // silent blank scene.
  const fleetGroup = new THREE.Group();
  fleetGroup.name = 'yuzu-fleet';
  scene.add(fleetGroup);

  // Cubes that are eligible for raycasting hit-tests. Maintained alongside
  // fleetGroup so the raycaster doesn't have to walk wireframe LineSegments
  // (cheaper + avoids hit-test on the outline material).
  const cubeMeshes = [];

  // PR 7: process dots eligible for raycasting hit-tests. Maintained as a
  // flat array (rather than walking the per-cube subgroups) so the
  // raycaster does one Object3D.matrixWorld read per dot instead of
  // recursing through each cube's child graph. cleared in clearFleet().
  const processMeshes = [];

  // gov R6 happy-S1 / UP-20: cubes carry a wireframe LineSegments child
  // (added in buildCube). The straight `for child of fleetGroup.children`
  // walk only sees the cube — wireframe geometry + material would never
  // get disposed and VRAM would leak proportional to N * #refills. PR 11
  // adds a 60s background refresher; without recursive disposal the leak
  // would be cumulative. Use traverse() so every descendant material +
  // geometry + texture lands on dispose().
  function disposeNode(obj) {
    if (obj.material) {
      const mats = Array.isArray(obj.material) ? obj.material : [obj.material];
      for (let i = 0; i < mats.length; i++) {
        if (mats[i].map) mats[i].map.dispose();
        mats[i].dispose();
      }
    }
    if (obj.geometry) obj.geometry.dispose();
  }
  function clearFleet() {
    while (fleetGroup.children.length > 0) {
      const child = fleetGroup.children[0];
      fleetGroup.remove(child);
      // Recurse to release wireframe LineSegments + sprite-internal
      // textures + the PR 7 per-machine processGroup subtree. Without
      // recursion, every refill leaks N machines × M processes worth of
      // SphereGeometry + MeshBasicMaterial into VRAM (PR 11 adds 60s
      // background refresher; this would be cumulative).
      child.traverse(disposeNode);
    }
    cubeMeshes.length = 0;
    // PR 7: traversal already disposed every dot inside each cube's
    // processGroup; just drop the flat raycast index alongside cubeMeshes.
    processMeshes.length = 0;
  }

  function addMachines(machines) {
    clearFleet();
    const placements = layoutMachines(machines);
    for (let i = 0; i < placements.length; i++) {
      const p = placements[i];
      const cube = buildCube(p.machine);
      cube.position.set(p.x, p.y, p.z);
      fleetGroup.add(cube);
      cubeMeshes.push(cube);
      const label = buildHostnameLabel(p.machine.hostname);
      label.position.set(p.x, p.y + CUBE_SIZE * 0.85, p.z);
      fleetGroup.add(label);

      // PR 7: per-machine process subgroup. Attached as a child of the
      // cube (NOT as a sibling under fleetGroup) so the dots inherit
      // every transform on the cube — no synchronisation required as
      // the OrbitControls camera moves or as PR 11 toggles per-cube
      // visibility for LOD culling. Layout coordinates are cube-local.
      const procs = Array.isArray(p.machine && p.machine.processes)
        ? p.machine.processes : [];
      if (procs.length > 0) {
        const processGroup = new THREE.Group();
        processGroup.name = 'yuzu-processes';
        cube.add(processGroup);
        const procPlacements = placeProcessesInCube(procs, CUBE_SIZE);
        for (let j = 0; j < procPlacements.length; j++) {
          const pp = procPlacements[j];
          const dot = buildProcessNode(pp.process);
          dot.position.set(pp.x, pp.y, pp.z);
          processGroup.add(dot);
          processMeshes.push(dot);
        }
      }
    }
  }

  // ── PR 6: tooltip ─────────────────────────────────────────────────────
  // Lazily created div; appended to viz-root so it inherits the page's
  // stacking + cleanup. Position is updated in screen space on
  // mousemove.
  let _tooltip = null;
  function ensureTooltip() {
    if (_tooltip) return _tooltip;
    _tooltip = document.createElement('div');
    _tooltip.id = 'viz-tooltip';
    _tooltip.style.cssText =
      'position:absolute;pointer-events:none;background:rgba(0,0,0,0.85);' +
      'color:#fff;padding:0.4rem 0.6rem;border-radius:0.25rem;' +
      'font-size:0.78rem;line-height:1.3;z-index:6;display:none;' +
      // gov R6 UP-3: hostname / os come from agent payloads. Without
      // word-break + overflow caps a 100KB hostname turns the tooltip
      // into a screen-filling rectangle on hover. max-width caps the
      // visual footprint; word-break:break-all forces wrapping inside
      // a long unbroken string; max-height clips the worst case.
      'max-width:320px;max-height:240px;overflow:hidden;' +
      'word-break:break-all;border:1px solid #444;';
    root.appendChild(_tooltip);
    return _tooltip;
  }
  function hideTooltip() {
    if (_tooltip) _tooltip.style.display = 'none';
  }
  function showTooltip(machine, evt) {
    const tip = ensureTooltip();
    // gov R6 UP-1 / sec-MEDIUM: agent-controlled `processes` / `connections`
    // could be a non-array masquerading as one (e.g. {length: '<svg/onload=…>'}).
    // The `|| 0` short-circuit returns the malicious string and concatenates
    // it raw into innerHTML. Coerce through Number(...)|0 so any non-numeric
    // shape collapses to 0 and a 32-bit integer is the only thing the
    // template ever interpolates.
    const proc = Array.isArray(machine.processes) ? Number(machine.processes.length) | 0 : 0;
    const conn = Array.isArray(machine.connections) ? Number(machine.connections.length) | 0 : 0;
    const stale = machine.stale ? ' <span style="color:#f0c674">(stale)</span>' : '';
    tip.innerHTML =
      '<div style="font-weight:600;margin-bottom:0.2rem">' +
      escapeHtml(machine.hostname || '(unknown)') + stale + '</div>' +
      '<div>os: ' + escapeHtml(machine.os || '?') + '</div>' +
      '<div>processes: ' + proc + '</div>' +
      '<div>connections: ' + conn + '</div>';
    // Position relative to the canvas. Add a small offset so the cursor
    // doesn't sit on the tooltip and trigger flicker.
    const rect = canvas.getBoundingClientRect();
    tip.style.left = (evt.clientX - rect.left + 12) + 'px';
    tip.style.top = (evt.clientY - rect.top + 12) + 'px';
    tip.style.display = 'block';
  }
  // PR 7: process tooltip — pid / name / user / category. Same XSS
  // hardening as the cube tooltip: name + user are agent-controlled
  // strings, so every interpolated string field goes through escapeHtml,
  // and pid is coerced through `Number(...) | 0` so an agent-controlled
  // non-numeric pid collapses to 0 rather than getting concatenated raw.
  // The shared #viz-tooltip element inherits the cube tooltip's
  // max-width/max-height/word-break caps so a 100KB process name cannot
  // DoS layout (gov R6 UP-3 mirror).
  function showProcessTooltip(process, evt) {
    const tip = ensureTooltip();
    const pid = Number(process && process.pid) | 0;
    tip.innerHTML =
      '<div style="font-weight:600;margin-bottom:0.2rem">' +
      'pid ' + pid + ': ' + escapeHtml((process && process.name) || '(unknown)') + '</div>' +
      '<div>user: ' + escapeHtml((process && process.user) || '?') + '</div>' +
      '<div>category: ' + escapeHtml((process && process.category) || 'other') + '</div>';
    const rect = canvas.getBoundingClientRect();
    tip.style.left = (evt.clientX - rect.left + 12) + 'px';
    tip.style.top = (evt.clientY - rect.top + 12) + 'px';
    tip.style.display = 'block';
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return c === '&' ? '&amp;' :
             c === '<' ? '&lt;' :
             c === '>' ? '&gt;' :
             c === '"' ? '&quot;' : '&#39;';
    });
  }

  const _ray = new THREE.Raycaster();
  const _ndc = new THREE.Vector2();
  function onMouseMove(evt) {
    if (cubeMeshes.length === 0 && processMeshes.length === 0) {
      hideTooltip();
      return;
    }
    const rect = canvas.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    _ndc.x = ((evt.clientX - rect.left) / rect.width) * 2 - 1;
    _ndc.y = -((evt.clientY - rect.top) / rect.height) * 2 + 1;
    _ray.setFromCamera(_ndc, camera);
    // PR 7: process raycast wins over cube raycast. Process dots live
    // INSIDE the translucent cube; if we let intersectObjects pick the
    // closest hit across both sets, the cube's outer face always wins
    // by distance and the operator can never hover a process dot
    // through the translucent shell. Raycast processMeshes first; only
    // fall through to cubeMeshes when no process is intersected.
    if (processMeshes.length > 0) {
      const procHits = _ray.intersectObjects(processMeshes, false);
      if (procHits.length > 0 && procHits[0].object.userData.yuzuProcess) {
        showProcessTooltip(procHits[0].object.userData.yuzuProcess, evt);
        return;
      }
    }
    const hits = _ray.intersectObjects(cubeMeshes, false);
    if (hits.length > 0 && hits[0].object.userData.yuzuMachine) {
      showTooltip(hits[0].object.userData.yuzuMachine, evt);
    } else {
      hideTooltip();
    }
  }
  canvas.addEventListener('mousemove', onMouseMove);
  canvas.addEventListener('mouseleave', hideTooltip);

  // ── PR 6: data fetch ──────────────────────────────────────────────────
  // Asynchronous because the cache-cold path on the server can take up to
  // 5 s (fleet-wide tar.fleet_snapshot dispatch). Surface failures via
  // #viz-error rather than letting the scene sit empty.
  function setError(msg) {
    const e = root.querySelector('#viz-error');
    if (!e) return;
    e.textContent = msg;
    e.classList.add('shown');
  }
  function clearError() {
    const e = root.querySelector('#viz-error');
    if (e) e.classList.remove('shown');
  }

  function fetchAndRender() {
    const url = root.getAttribute('data-yuzu-viz-url');
    if (!url) {
      setError('viz: data-yuzu-viz-url not set on #viz-root');
      return Promise.resolve(null);
    }
    return fetch(url, {credentials: 'same-origin', headers: {'Accept': 'application/json'}})
      .then(function (r) {
        // gov R5 UP-17: an operator who was admin on page-load can be
        // demoted mid-session. The fetch returns 403 (RBAC denied) and
        // the renderer must surface that explicitly rather than show a
        // blank scene. 401 means the session itself died; reload routes
        // through the server's auth middleware.
        if (r.status === 401) {
          // gov R6 UP-15: scrub any cubes we'd previously rendered so the
          // operator doesn't see "live data" cubes alongside an "access
          // denied" overlay -- mixed signals would imply they still see
          // the fleet despite the denial.
          clearFleet();
          setError('Session expired. Please reload the page.');
          return null;
        }
        if (r.status === 403) {
          clearFleet();
          setError('Access denied. Your role no longer permits viewing the fleet topology.');
          return null;
        }
        if (r.status === 503) {
          clearFleet();
          setError('Fleet visualization is currently disabled by an administrator.');
          return null;
        }
        if (r.status === 413) {
          // gov R6 UP-6: opaque "HTTP 413" leaves the operator without an
          // actionable next step. Name the cap so they know what to ask
          // an admin to raise (or to scope the fleet down via management
          // groups).
          clearFleet();
          setError('Fleet exceeds the configured machines_max cap. Ask an administrator to ' +
                   'raise --viz-machines-max or scope the request via a management group.');
          return null;
        }
        if (!r.ok) {
          clearFleet();
          setError('Failed to fetch fleet topology (HTTP ' + r.status + '). Try reloading.');
          return null;
        }
        return r.json();
      })
      .then(function (data) {
        if (!data) return null;
        // gov R6 UP-10: a malformed payload (TypeError on machines.slice or
        // similar) would otherwise fall through to the network catch and
        // be misclassified as a network error. Validate the shape first so
        // the operator gets a payload-error message instead.
        if (typeof data !== 'object' || data === null) {
          setError('Malformed topology payload (not an object).');
          return null;
        }
        if (data.schema !== 'fleet_topology.v1') {
          // gov R6 UP-8: future schema bump -> hint the operator to reload
          // their browser cache, since the renderer is module-cached.
          setError('Unexpected topology schema: ' + (data.schema || '<missing>') +
                   '. Reload the page (Ctrl+Shift+R) to pick up the new dashboard.');
          return null;
        }
        // gov R6 UP-9 / UP-10: distinguish "machines field missing/null"
        // (server bug) and "machines is wrong type" (schema regression)
        // from "0 machines" (legitimate empty fleet). Each gets a distinct
        // operator-visible message.
        if (data.machines === undefined || data.machines === null) {
          clearError();
          clearFleet();
          setError('Server returned no machines field. This is a server-side bug; check the server log.');
          return null;
        }
        if (!Array.isArray(data.machines)) {
          clearError();
          clearFleet();
          setError('Malformed topology payload (machines is not an array).');
          return null;
        }
        clearError();
        addMachines(data.machines);
        return data;
      })
      .catch(function (err) {
        // gov R5 UP-17: network failures land here too; the user just
        // gets the same friendly overlay rather than a console-only
        // exception. SyntaxError from r.json() also lands here (truncated
        // body) -- distinguish in the message so the operator can tell
        // "connection broken" from "server returned bad JSON".
        const m = (err && err.message) ? err.message : 'network error';
        const kind = (err && err.name === 'SyntaxError')
                       ? 'Malformed JSON from server (truncated response or proxy issue)'
                       : 'Cannot reach server';
        clearFleet();
        setError(kind + ': ' + m);
        return null;
      });
  }

  // ── Render loop ────────────────────────────────────────────────────────
  // Continuous rAF: keeps the OrbitControls damping animation smooth and
  // gives WASD frames somewhere to apply. PR 11 may throttle to render-
  // on-input once the scene complexity (PR 7+ process nodes, PR 8/9 edges)
  // makes the cost more meaningful.
  function tick() {
    // gov R4 UP-3: when the GL context is lost, skip render() to avoid
    // spamming "context-lost" warnings. The handler above already
    // surfaced #viz-error; the operator must reload to recover.
    //
    // gov R5 UP-7: defensive Number.isFinite check on camera.position.
    // OrbitControls + WASD math should never push the camera into NaN
    // territory, but a single bad input can cascade through every frame
    // (renderer.render with NaN matrices crashes WebGL on some drivers).
    // Reset to a sane default and fall through to render so the operator
    // sees something rather than a hung scene.
    if (!_contextLost) {
      // gov R6 architect NICE-2: a poisoned `_offset` add can land non-
      // finite values on BOTH camera.position and controls.target. Reset
      // only camera.position would be insufficient because the next
      // `controls.update()` call recomputes camera.position from the bad
      // target, re-poisoning it within one frame. Reset both, then
      // controls.update() so the target write takes effect for this frame.
      const cp = camera.position;
      const ct = controls.target;
      if (!Number.isFinite(cp.x) || !Number.isFinite(cp.y) || !Number.isFinite(cp.z) ||
          !Number.isFinite(ct.x) || !Number.isFinite(ct.y) || !Number.isFinite(ct.z)) {
        camera.position.set(35, 30, 35);
        controls.target.set(0, 0, 0);
        camera.lookAt(0, 0, 0);
      }
      applyWasdPan();
      controls.update();
      renderer.render(scene, camera);
    }
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);

  // Kick off the initial topology fetch once the scene is alive. Don't
  // block the rAF loop — by the time the data lands, the scaffold is
  // already rendering, and addMachines() just splices into fleetGroup.
  fetchAndRender();

  // Expose for dev-console inspection AND test code (idempotency guard,
  // mount-time assertions, manual data refresh). Not a public API.
  // gov R6 architect SHOULD-3: dev-console handles live under __internal
  // so the namespace itself signals "do not depend on this" to userscripts
  // and third-party integrations. Tests use the same path.
  const dev = window.YuzuViz.__internal;
  dev.scene = scene;
  dev.camera = camera;
  dev.renderer = renderer;
  dev.controls = controls;
  dev.heldKeys = heldKeys;
  dev.root = root;
  dev.fleetGroup = fleetGroup;
  dev.cubeMeshes = cubeMeshes;
  dev.processMeshes = processMeshes;
  dev.addMachines = addMachines;
  dev.fetchAndRender = fetchAndRender;
}

// Mount on initial DOMContentLoaded (full page nav) and on htmx:afterSettle
// (in case the page is reached via an HTMX swap inside a parent shell).
// mount() itself is idempotent so multiple firings are safe.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mount, { once: true });
} else {
  mount();
}
document.body.addEventListener('htmx:afterSettle', mount);
