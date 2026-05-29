'use strict';

// Cedar & Vale deck — the machine behind the slides.
//
// A fixed brass-clockwork backdrop: a deterministic train of interlocking,
// properly-meshing gears — a Victorian analytical-engine "mind" the deck runs
// on. The layout and motion are fully deterministic (no randomness):
//
//   * Constant module M (tooth size) across every gear, so teeth interlock.
//   * Each gear is placed meshing with one parent at the exact pitch distance
//     (centre spacing = pitchRadius(parent) + pitchRadius(child)).
//   * Rotation is a pure function of a single master drive angle: a meshing
//     pair turns in OPPOSITE directions with speed inversely proportional to
//     tooth count (omega_i * N_i = omega_j * N_j) — real gear ratios. So the
//     whole field is one coherent mechanism.
//   * On each slide transition the master angle briefly accelerates ("thinking
//     harder"), then eases back. Position is fixed — the backdrop never moves.
//
// Also drives per-slide background <video>: only the active slide's clip plays.
//
// Loaded before impress().init() so the step listeners are attached before the
// first stepenter fires.

(function () {
  var reduceMotion = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // --- Per-slide background video: play only the active slide's <video>. ---
  document.addEventListener('impress:stepenter', function (e) {
    var v = e.target && e.target.querySelector && e.target.querySelector('video.slide-video');
    if (v && !reduceMotion) {
      try { v.currentTime = 0; var pr = v.play(); if (pr && pr.catch) pr.catch(function () {}); } catch (_) {}
    }
  });
  document.addEventListener('impress:stepleave', function (e) {
    var v = e.target && e.target.querySelector && e.target.querySelector('video.slide-video');
    if (v) { try { v.pause(); } catch (_) {} }
  });

  var svg = document.querySelector('.machine');
  if (!svg) return;
  var SVGNS = 'http://www.w3.org/2000/svg';
  var M = 7;                      // module: tooth size, constant so gears mesh

  // Gear train. `from` is the index of the gear this one meshes with; `a` is the
  // absolute angle (rad) of the line joining their centres. The first gear is
  // the anchor (absolute x,y). Tooth counts set the gear sizes and ratios. This
  // weaves a connected mechanism across the 1600x900 backdrop.
  // Three meshing clusters spread across the 1600x900 field so the backdrop is
  // covered to the corners. Each cluster is its own connected, interlocking
  // train (driven from its anchor); a is the absolute angle of the centre line.
  var spec = [
    // Cluster A — upper left
    { N: 30, x: 250, y: 170, color: 'gear--gold',   depth: 'g-mid'  }, // 0 anchor
    { N: 18, from: 0,  a:  0.70, color: 'gear--silver', depth: 'g-near' }, // 1
    { N: 24, from: 1,  a: -0.30, color: 'gear--gold',   depth: 'g-far'  }, // 2
    { N: 16, from: 0,  a:  2.45, color: 'gear--silver', depth: 'g-mid'  }, // 3 left
    { N: 28, from: 1,  a:  1.55, color: 'gear--gold',   depth: 'g-far'  }, // 4 down
    { N: 14, from: 4,  a:  0.55, color: 'gear--silver', depth: 'g-near' }, // 5
    // Cluster B — upper right
    { N: 32, x: 1330, y: 210, color: 'gear--gold',   depth: 'g-far'  }, // 6 anchor
    { N: 18, from: 6,  a:  2.55, color: 'gear--silver', depth: 'g-mid'  }, // 7 left
    { N: 22, from: 6,  a:  1.45, color: 'gear--gold',   depth: 'g-near' }, // 8 down
    { N: 16, from: 8,  a:  0.30, color: 'gear--silver', depth: 'g-far'  }, // 9
    // Cluster C — lower band
    { N: 30, x: 470, y: 730, color: 'gear--silver', depth: 'g-mid'  }, // 10 anchor
    { N: 20, from: 10, a: -0.55, color: 'gear--gold',   depth: 'g-near' }, // 11 up
    { N: 26, from: 10, a:  0.30, color: 'gear--silver', depth: 'g-far'  }, // 12 right
    { N: 16, from: 12, a: -0.35, color: 'gear--gold',   depth: 'g-mid'  }, // 13
    { N: 34, from: 12, a:  0.45, color: 'gear--gold',   depth: 'g-far'  }, // 14 right
    { N: 18, from: 14, a: -0.25, color: 'gear--silver', depth: 'g-near' }, // 15
    { N: 22, from: 14, a:  0.85, color: 'gear--silver', depth: 'g-far'  }  // 16 right
  ];

  function pitch(N) { return M * N / 2; }

  // Flat-topped tooth profile (root -> rise -> tip -> fall), constant module so
  // tips reach into neighbours' tooth gaps and the gears read as interlocking.
  function gearPath(N) {
    var rp = pitch(N), ra = rp + M * 0.85, rd = rp - M * 1.0;
    var seg = 2 * Math.PI / N, gap = seg * 0.26, top = seg * 0.48;
    var d = '';
    for (var i = 0; i < N; i++) {
      var a0 = i * seg;
      var pts = [
        [rd, a0], [ra, a0 + gap], [ra, a0 + gap + top], [rd, a0 + gap + top + gap]
      ];
      for (var k = 0; k < 4; k++) {
        var r = pts[k][0], a = pts[k][1];
        var x = (Math.cos(a) * r).toFixed(2), y = (Math.sin(a) * r).toFixed(2);
        d += (i === 0 && k === 0 ? 'M ' : 'L ') + x + ' ' + y + ' ';
      }
    }
    return d + 'Z';
  }

  // Resolve positions + signed speeds from the spec tree.
  var gears = spec.map(function () { return null; });
  spec.forEach(function (s, i) {
    var rp = pitch(s.N), x, y, speed;
    if (s.from == null) { x = s.x; y = s.y; speed = 1; }
    else {
      var p = gears[s.from];
      var dist = p.rp + rp;
      x = p.x + Math.cos(s.a) * dist;
      y = p.y + Math.sin(s.a) * dist;
      speed = -p.speed * p.N / s.N;     // opposite direction, inverse tooth ratio
    }
    gears[i] = { N: s.N, rp: rp, x: x, y: y, speed: speed,
                 phase: (i * 53) % 360, color: s.color, depth: s.depth, el: null };
  });

  // Build the SVG: outer <g> translates to the gear centre, inner <g> rotates
  // about the local origin (= centre), so no transform-box gymnastics needed.
  svg.innerHTML = '';
  gears.forEach(function (g) {
    var outer = document.createElementNS(SVGNS, 'g');
    outer.setAttribute('transform', 'translate(' + g.x.toFixed(1) + ' ' + g.y.toFixed(1) + ')');
    outer.setAttribute('class', 'gear ' + g.color + ' ' + g.depth);

    var inner = document.createElementNS(SVGNS, 'g');
    var body = document.createElementNS(SVGNS, 'path');
    body.setAttribute('d', gearPath(g.N));
    body.setAttribute('fill', 'currentColor');
    inner.appendChild(body);

    var hub = document.createElementNS(SVGNS, 'circle');
    hub.setAttribute('r', (g.rp * 0.42).toFixed(1));
    hub.setAttribute('fill', 'none');
    hub.setAttribute('stroke', '#070a10');
    hub.setAttribute('stroke-width', (M * 0.9).toFixed(1));
    inner.appendChild(hub);

    var center = document.createElementNS(SVGNS, 'circle');
    center.setAttribute('r', (g.rp * 0.16).toFixed(1));
    center.setAttribute('fill', '#070a10');
    inner.appendChild(center);

    // a few spokes for clockwork detail
    var spokes = document.createElementNS(SVGNS, 'g');
    spokes.setAttribute('stroke', '#070a10');
    spokes.setAttribute('stroke-width', (M * 0.5).toFixed(1));
    for (var k = 0; k < 4; k++) {
      var ang = k * Math.PI / 2;
      var line = document.createElementNS(SVGNS, 'line');
      line.setAttribute('x1', (Math.cos(ang) * g.rp * 0.18).toFixed(1));
      line.setAttribute('y1', (Math.sin(ang) * g.rp * 0.18).toFixed(1));
      line.setAttribute('x2', (Math.cos(ang) * g.rp * 0.5).toFixed(1));
      line.setAttribute('y2', (Math.sin(ang) * g.rp * 0.5).toFixed(1));
      spokes.appendChild(line);
    }
    inner.appendChild(spokes);

    outer.appendChild(inner);
    svg.appendChild(outer);
    g.el = inner;
  });

  function applyRotations(master) {
    for (var i = 0; i < gears.length; i++) {
      var g = gears[i];
      g.el.setAttribute('transform', 'rotate(' + (g.phase + g.speed * master) + ')');
    }
  }

  if (reduceMotion) { applyRotations(0); return; }

  var BASE = 7;                  // driver angular speed, deg/sec
  var boost = 0;                 // 0..1, set on transition, decays
  var master = 0;
  var last = (window.performance || Date).now();
  function frame(now) {
    var dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    boost *= Math.pow(0.06, dt);          // ease back to idle (~1s)
    master += BASE * (1 + boost * 6) * dt; // driver angle; gears scale off it
    applyRotations(master);
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  // "Think harder" on each transition: briefly accelerate the whole train.
  document.addEventListener('impress:stepleave', function () { boost = 1; });
})();
