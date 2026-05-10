// Yuzu fleet visualization renderer (PR 5 + PR 6 of feat/viz-engine ladder).
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
// Mount contract: mount() runs idempotently on DOMContentLoaded and on
// `htmx:afterSettle`. It locates `[data-yuzu-viz-url]` (set in viz_page_ui.cpp
// on `#viz-root`) and bails early if already mounted (canvas survival
// invariant — HTMX swaps of `#viz-overlay-panel` must not blow away the
// WebGLRenderer's GPU context).
//
// PR 7+ fills in interior process nodes; PR 8/9 add intra- and inter-
// machine edges; PR 10 adds the vulnerability overlay.
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

// Single global handle the page can poke at from the dev console for
// debugging (window.YuzuViz.scene, .camera, .renderer, .controls).
window.YuzuViz = window.YuzuViz || {};

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

  function clearFleet() {
    while (fleetGroup.children.length > 0) {
      const child = fleetGroup.children[0];
      fleetGroup.remove(child);
      // Best-effort GPU resource release. Sprite materials hold canvas
      // textures we made here; cubes hold geometries + materials.
      if (child.material) {
        if (child.material.map) child.material.map.dispose();
        child.material.dispose();
      }
      if (child.geometry) child.geometry.dispose();
    }
    cubeMeshes.length = 0;
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
      'max-width:280px;border:1px solid #444;';
    root.appendChild(_tooltip);
    return _tooltip;
  }
  function hideTooltip() {
    if (_tooltip) _tooltip.style.display = 'none';
  }
  function showTooltip(machine, evt) {
    const tip = ensureTooltip();
    const proc = (machine.processes && machine.processes.length) || 0;
    const conn = (machine.connections && machine.connections.length) || 0;
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
    if (cubeMeshes.length === 0) { hideTooltip(); return; }
    const rect = canvas.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    _ndc.x = ((evt.clientX - rect.left) / rect.width) * 2 - 1;
    _ndc.y = -((evt.clientY - rect.top) / rect.height) * 2 + 1;
    _ray.setFromCamera(_ndc, camera);
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
          setError('Session expired. Please reload the page.');
          return null;
        }
        if (r.status === 403) {
          setError('Access denied. Your role no longer permits viewing the fleet topology.');
          return null;
        }
        if (r.status === 503) {
          setError('Fleet visualization is currently disabled by an administrator.');
          return null;
        }
        if (!r.ok) {
          setError('Failed to fetch fleet topology (HTTP ' + r.status + '). Try reloading.');
          return null;
        }
        return r.json();
      })
      .then(function (data) {
        if (!data) return null;
        if (data.schema !== 'fleet_topology.v1') {
          setError('Unexpected topology schema: ' + (data.schema || '<missing>'));
          return null;
        }
        clearError();
        addMachines(data.machines || []);
        return data;
      })
      .catch(function (err) {
        // gov R5 UP-17: network failures land here too; the user just
        // gets the same friendly overlay rather than a console-only
        // exception.
        setError('Cannot reach server: ' + (err && err.message ? err.message : 'network error'));
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
      if (!Number.isFinite(camera.position.x) ||
          !Number.isFinite(camera.position.y) ||
          !Number.isFinite(camera.position.z)) {
        camera.position.set(35, 30, 35);
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
  window.YuzuViz.scene = scene;
  window.YuzuViz.camera = camera;
  window.YuzuViz.renderer = renderer;
  window.YuzuViz.controls = controls;
  window.YuzuViz.heldKeys = heldKeys;
  window.YuzuViz.root = root;
  window.YuzuViz.fleetGroup = fleetGroup;
  window.YuzuViz.cubeMeshes = cubeMeshes;
  window.YuzuViz.addMachines = addMachines;
  window.YuzuViz.fetchAndRender = fetchAndRender;
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
