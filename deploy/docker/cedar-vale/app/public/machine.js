'use strict';

// Cedar & Vale deck — the machine behind the slides.
//
// Murky gold/silver gears (markup lives in the .machine <svg> the app injects)
// idle with a slow creep and spin up briefly on each slide transition, as if a
// friendly, unscary mechanism is what moves the deck. The boost is driven off
// impress.js step events; rotation is applied per-gear via CSS transform with
// transform-box:fill-box so each gear turns about its own centre (see deck.css).
//
// Loaded before impress().init() so the step-event listeners are attached
// before the first stepenter fires.

(function () {
  var reduceMotion = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // --- Per-slide background video: play only the active slide's <video>, pause
  // the rest, so at most one clip decodes at a time. Present only on slides that
  // have a bg<N>.webm (the server emits the element conditionally). Runs even if
  // there are no gears; under reduced-motion the poster JPG shows (no autoplay).
  document.addEventListener('impress:stepenter', function (e) {
    var v = e.target && e.target.querySelector && e.target.querySelector('video.slide-video');
    if (v && !reduceMotion) {
      try { v.currentTime = 0; var p = v.play(); if (p && p.catch) p.catch(function () {}); } catch (_) {}
    }
  });
  document.addEventListener('impress:stepleave', function (e) {
    var v = e.target && e.target.querySelector && e.target.querySelector('video.slide-video');
    if (v) { try { v.pause(); } catch (_) {} }
  });

  var gears = Array.prototype.slice.call(document.querySelectorAll('.machine use'));
  if (!gears.length) return;

  // Each gear gets a starting angle and a slow idle angular velocity (deg/s),
  // alternating direction so neighbours look meshed.
  var state = gears.map(function (el, i) {
    return {
      el: el,
      angle: (i * 47) % 360,
      idle: (i % 2 ? -1 : 1) * (2.2 + (i % 3) * 1.6)
    };
  });

  if (reduceMotion) {
    state.forEach(function (s) { s.el.style.transform = 'rotate(' + s.angle + 'deg)'; });
    return;
  }

  var boost = 0;                       // 0..1, set to 1 on transition, decays
  var last = (window.performance || Date).now();

  function frame(now) {
    var dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    boost *= Math.pow(0.05, dt);       // exponential decay back to idle (~1s)
    var k = 1 + boost * 9;             // up to ~10x faster mid-transition
    for (var i = 0; i < state.length; i++) {
      var s = state[i];
      s.angle = (s.angle + s.idle * k * dt) % 360;
      s.el.style.transform = 'rotate(' + s.angle + 'deg)';
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  // impress fires step events on #impress; they bubble to document.
  document.addEventListener('impress:stepleave', function () { boost = 1; });

  // Subtle whole-machine parallax nudge each transition, eased back via the CSS
  // transition on .machine — "the mechanism shifts as it moves the slide".
  var machine = document.querySelector('.machine');
  if (machine) {
    document.addEventListener('impress:stepleave', function () {
      var dx = (Math.random() * 2 - 1) * 14;
      var dy = (Math.random() * 2 - 1) * 10;
      machine.style.transform = 'translate(' + dx + 'px,' + dy + 'px) scale(1.02)';
    });
    document.addEventListener('impress:stepenter', function () {
      machine.style.transform = '';
    });
  }
})();
