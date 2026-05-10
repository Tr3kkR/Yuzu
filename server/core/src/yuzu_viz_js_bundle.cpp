// Yuzu fleet visualization renderer (PR 5 of feat/viz-engine ladder).
//
// This is the empty-scene scaffold: scene + perspective camera + ambient +
// directional light + ground grid + axes helper, with OrbitControls drag-
// rotate / wheel-zoom and a custom WASD pan listener (OrbitControls'
// `enablePan` is off so WASD owns translation).
//
// Mount contract: mount() runs idempotently on DOMContentLoaded and on
// `htmx:afterSettle`. It locates `[data-yuzu-viz-url]` (set in viz_page_ui.cpp
// on `#viz-root`) and bails early if already mounted (canvas survival
// invariant — HTMX swaps of `#viz-overlay-panel` must not blow away the
// WebGLRenderer's GPU context).
//
// PR 6+ fills in the renderer.fetchTopology() body to draw cubes / process
// nodes / edges. PR 5 ships the controls + scene only so they can be
// validated in isolation.
//
// Load contract:
//   <script type="importmap"> maps "three" -> /static/three.module.min.js
//                       and    "three/addons/controls/OrbitControls.js"
//                              -> /static/three-orbit-controls.js
//   <script type="module" src="/static/yuzu-viz.js"> runs this file.
//
// Hand-written, ~6 KB, comfortably under MSVC's 16,380-byte raw-string
// limit so no chunking needed (mirrors charts_js_bundle.cpp).

#include <string>

namespace yuzu::server {

// `extern const` so the symbol survives namespace-scope linkage; mirrors
// kYuzuChartsJs in charts_js_bundle.cpp.
extern const std::string kYuzuVizJs = R"JS(
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

  // ── Render loop ────────────────────────────────────────────────────────
  // Empty placeholder for PR 6+. Today the loop just spins the camera-
  // damping animation forward and renders the static scene (grid + axes).
  // PR 6 will wire `.fetchTopology()` -> add machine cubes; PR 11 may
  // throttle to requestAnimationFrame-on-input rather than continuous.
  function tick() {
    // gov R4 UP-3: when the GL context is lost, skip render() to avoid
    // spamming "context-lost" warnings. The handler above already
    // surfaced #viz-error; the operator must reload to recover.
    if (!_contextLost) {
      applyWasdPan();
      controls.update();
      renderer.render(scene, camera);
    }
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);

  // Expose for dev-console inspection. NOT a public API; PR 11 may rip
  // this out. Test code uses the same hook to assert mount succeeded.
  window.YuzuViz.scene = scene;
  window.YuzuViz.camera = camera;
  window.YuzuViz.renderer = renderer;
  window.YuzuViz.controls = controls;
  window.YuzuViz.heldKeys = heldKeys;
  window.YuzuViz.root = root;
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
)JS";

} // namespace yuzu::server
