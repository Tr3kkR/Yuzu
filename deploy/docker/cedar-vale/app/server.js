'use strict';

// Cedar & Vale demo — "app" tier.
//
// Express server that renders the impress.js (Prezi-style) deck from slide rows
// stored in the "db" tier (Postgres). Two jobs beyond serving HTML:
//
//   1. Hold the node->Postgres TCP socket ESTABLISHED so the fleet-viz "blue
//      tube" between the app and db tiers stays drawn even when nobody is
//      viewing. We do this with a pg Pool that never closes idle connections
//      (idleTimeoutMillis: 0) plus a periodic `SELECT 1` keepalive.
//
//   2. Expose GET /healthz with NO database dependency, so Envoy's active
//      health check (which keeps the frontend->app tube lit) succeeds even
//      while Postgres is still starting.

const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const PORT = parseInt(process.env.APP_PORT || '3000', 10);
const KEEPALIVE_MS = parseInt(process.env.DB_KEEPALIVE_MS || '5000', 10);

// Connection config comes from standard PG* env vars (set in compose). The host
// is the db tier's compose service name, which resolves to its bridge IP — that
// is what makes the outbound socket an InternalFleet edge the topology store can
// resolve to the db agent (and therefore a rendered tube).
const pool = new Pool({
  host: process.env.PGHOST || 'cv-db',
  port: parseInt(process.env.PGPORT || '5432', 10),
  user: process.env.PGUSER || 'cedar',
  password: process.env.PGPASSWORD || 'vale',
  database: process.env.PGDATABASE || 'cedarvale',
  max: 2,
  idleTimeoutMillis: 0,        // never close idle conns — keep the socket hot
  allowExitOnIdle: false,
});

pool.on('error', (err) => {
  // A backend restart drops pooled conns; log and let the pool re-establish.
  console.error('[pg pool] idle client error:', err.message);
});

// Keepalive: one trivial round-trip every few seconds keeps at least one
// connection ESTABLISHED so the app->db tube never flickers off at idle.
setInterval(() => {
  pool.query('SELECT 1').catch((e) => console.error('[pg keepalive]', e.message));
}, KEEPALIVE_MS);

const app = express();
app.use('/public', express.static(path.join(__dirname, 'public')));

// DB-free liveness — Envoy health-checks this to hold the frontend->app tube.
app.get('/healthz', (_req, res) => res.type('text/plain').send('ok\n'));

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

// The hidden machine: murky gold/silver gears far behind the slides. One gear
// <symbol> reused at several sizes/depths; machine.js spins each in place and
// nudges the whole field on every transition. aria-hidden — purely decorative.
const MACHINE_SVG = `
  <svg class="machine" aria-hidden="true" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid slice">
    <defs>
      <symbol id="cv-gear" viewBox="-50 -50 100 100">
        <circle r="46" fill="none" stroke="currentColor" stroke-width="16" stroke-dasharray="13 14"/>
        <circle r="37" fill="currentColor"/>
        <circle r="16" fill="none" stroke="#070a10" stroke-width="7"/>
        <circle r="6" fill="#070a10"/>
      </symbol>
    </defs>
    <use href="#cv-gear" class="gear--gold g-far"   x="-60"  y="-80"  width="440" height="440"/>
    <use href="#cv-gear" class="gear--silver g-far" x="1240" y="-140" width="520" height="520"/>
    <use href="#cv-gear" class="gear--gold g-mid"   x="1180" y="360"  width="320" height="320"/>
    <use href="#cv-gear" class="gear--silver g-far" x="-180" y="560"  width="560" height="560"/>
    <use href="#cv-gear" class="gear--gold g-mid"   x="600"  y="720"  width="260" height="260"/>
    <use href="#cv-gear" class="gear--silver g-near" x="300" y="430"  width="210" height="210"/>
  </svg>`;

function renderDeck(rows) {
  const steps = rows.map((r) => `
      <div id="${esc(r.slug)}" class="step slide-${esc(r.slug)}"
           data-x="${r.data_x}" data-y="${r.data_y}" data-z="${r.data_z}"
           data-rotate="${r.data_rotate}" data-scale="${r.data_scale}">
        ${r.body_html}
      </div>`).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=1024">
  <title>Agentic Colleagues &middot; Cedar &amp; Vale</title>
  <link rel="stylesheet" href="/public/deck.css">
</head>
<body class="impress-not-supported">
${MACHINE_SVG}
  <div class="fallback-message">
    <p>Your browser <b>doesn't support the features required</b> by impress.js, so you're seeing a flat fallback.</p>
  </div>
  <div id="impress" data-transition-duration="1100" data-width="1920" data-height="1080"
       data-max-scale="6" data-min-scale="0.4" data-perspective="1000">
${steps}
  </div>
  <img class="crest" src="/public/crest.png" alt="Barony of Alyth" aria-hidden="true">
  <div class="hint">Use &larr; / &rarr; (or Space) to move through the deck. Served live from Postgres.</div>
  <script src="/public/machine.js"></script>
  <script src="/public/impress.js"></script>
  <script>impress().init();</script>
</body>
</html>`;
}

app.get('/', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT position, slug, title, body_html, data_x, data_y, data_z, data_rotate, data_scale FROM slides ORDER BY position'
    );
    if (rows.length === 0) {
      res.status(503).type('text/html').send('<h1>Deck is empty</h1><p>No slides in the database yet.</p>');
      return;
    }
    res.type('text/html').send(renderDeck(rows));
  } catch (e) {
    // Postgres not ready yet (first boot) — return a warming page that
    // auto-refreshes, rather than a hard 500.
    res.status(503).type('text/html').send(
      `<!doctype html><meta http-equiv="refresh" content="2">` +
      `<body style="font-family:sans-serif;background:#04070c;color:#cdd9e5;padding:3rem">` +
      `<h1>Warming up…</h1><p>Waiting for the database tier (${esc(e.message)}).</p></body>`
    );
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[cedar-vale app] listening on :${PORT} (db ${process.env.PGHOST || 'cv-db'}:${process.env.PGPORT || '5432'})`);
});
