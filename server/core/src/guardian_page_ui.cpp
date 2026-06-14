// Guardian detail page shell — full-page drill-down for a single Guard or
// Baseline (replaces the cramped detail modal). Sibling of /guardian.
//
// One parameterised shell serves both /guardian/baseline/<id> and
// /guardian/guard/<id>: the page-route handler substitutes {{TITLE}} (browser
// tab title) and {{FRAGMENT}} (the page-content fragment URL), then the mount
// hx-gets that fragment on load. This mirrors the Fleet-Viz host page
// (viz_host_page_ui.cpp): a static shell + server-side token substitution +
// an hx-get fragment, so the heavy renderer stays a testable fragment method.
//
// Product UI — HTMX, server-rendered, dark-theme only. Palette comes from
// /static/yuzu.css (--bg/--surface/--border/--fg/--muted/--green/--yellow/
// --red/--accent/--mono); the page-specific component CSS lives in the inline
// <style> below because those classes (.gp-*) are not part of the shared
// stylesheet. Do NOT apply the `frontend-design` plugin here.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kGuardianDetailPageHtml =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{TITLE}}</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    .gp-wrap { max-width: 1100px; margin: 1.5rem auto; padding: 0 1.5rem; }
    .gp-loading { color: var(--muted); padding: 2rem 0; }
    .gp-back { font-size: 0.78rem; color: var(--accent); display: inline-block;
               margin-bottom: 0.75rem; text-decoration: none; }
    .gp-back:hover { text-decoration: underline; }

    /* page header: title + actions */
    .gp-head { display: flex; align-items: flex-start; justify-content: space-between;
               gap: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.9rem; }
    .gp-head h1 { font-size: 1.4rem; font-weight: 700; }
    .gp-titleline { display: flex; align-items: center; gap: 0.55rem; flex-wrap: wrap; }
    .gp-sub { font-size: 0.78rem; color: var(--muted); margin-top: 0.35rem; }
    .gp-actions { display: flex; gap: 0.45rem; flex-shrink: 0; }

    .gp-sech { font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.06em;
               color: var(--muted); font-weight: 700; margin: 1.3rem 0 0.5rem; }
    .gp-note { font-size: 0.74rem; color: var(--muted); margin-top: 0.5rem; }
    .gp-note b { color: #a5d6ff; }

    /* lifecycle / severity / mode pills */
    .gp-pill { font-size: 0.62rem; font-weight: 700; text-transform: uppercase;
               letter-spacing: 0.03em; border-radius: 0.3rem; padding: 0.1rem 0.45rem;
               border: 1px solid var(--border); }
    .gp-pill.dep { color: var(--green); border-color: rgba(78,210,126,0.5); }
    .gp-pill.draft { color: var(--muted); }
    .gp-pill.sev-critical, .gp-pill.sev-high { color: var(--red); border-color: rgba(255,87,101,0.5); }
    .gp-pill.sev-medium { color: var(--yellow); border-color: rgba(255,204,0,0.45); }
    .gp-pill.sev-low { color: #a5d6ff; }
    .gp-pill.observe { color: #a5d6ff; }
    .gp-pill.enforce { color: var(--yellow); border-color: rgba(255,204,0,0.45); }

    /* compliance hero */
    .gp-hero { display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap; }
    .gp-pct { font-size: 2.1rem; font-weight: 700; color: var(--fg); line-height: 1; }
    .gp-pct small { display: block; font-size: 0.64rem; color: var(--muted); font-weight: 400;
                    text-transform: uppercase; letter-spacing: 0.05em; }
    .gp-bar { display: flex; height: 18px; border-radius: 4px; overflow: hidden;
              border: 1px solid var(--border); }
    .gp-bar > span { display: flex; align-items: center; justify-content: center;
                     font-size: 0.58rem; color: #04101f; font-weight: 700; }
    .gp-legend { display: flex; flex-wrap: wrap; gap: 0.9rem; margin-top: 0.4rem;
                 font-size: 0.64rem; color: var(--muted); }
    .gp-legend i { display: inline-block; width: 0.55rem; height: 0.55rem; border-radius: 2px;
                   margin-right: 0.3rem; vertical-align: middle; }
    .gp-legend b { color: var(--fg); }

    /* stat tiles */
    .gp-tiles { display: flex; flex-wrap: wrap; gap: 0.55rem; margin-top: 0.9rem; }
    .gp-tile { background: var(--surface); border: 1px solid var(--border);
               border-radius: 0.5rem; padding: 0.55rem 0.8rem; min-width: 120px; flex: 1; }
    .gp-tile .n { font-size: 1.4rem; font-weight: 700; color: var(--fg); line-height: 1.1; }
    .gp-tile .l { font-size: 0.62rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .gp-tile .sx { font-size: 0.62rem; color: var(--muted); margin-top: 0.12rem; }
    .gp-tile .n.good { color: var(--green); } .gp-tile .n.warn { color: var(--yellow); }
    .gp-tile .n.bad { color: var(--red); } .gp-tile .n.unk { color: #5b6b80; }
    .gp-tile .n.info { color: var(--accent); } .gp-tile .n.mute { color: var(--muted); }

    /* spec grid (what a guard checks) */
    .gp-spec { display: grid; grid-template-columns: auto 1fr; gap: 0.3rem 1rem;
               font-size: 0.78rem; background: var(--surface); border: 1px solid var(--border);
               border-radius: 0.5rem; padding: 0.7rem 0.9rem; }
    .gp-spec .k { color: var(--muted); }
    .gp-spec code { font-family: var(--mono); color: #a5d6ff; overflow-wrap: anywhere; }

    /* tables */
    .gp-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
    .gp-table th { text-align: left; padding: 0.42rem 0.55rem; border-bottom: 2px solid var(--border);
                   color: var(--muted); font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .gp-table td { padding: 0.42rem 0.55rem; border-bottom: 1px solid var(--border); }
    .gp-table tr.click { cursor: pointer; }
    .gp-table tr.click:hover td { background: var(--mds-color-state-hover); }
    .gp-table a { color: var(--fg); font-weight: 600; text-decoration: none; }
    .gp-table a:hover { color: var(--accent); }
    .gp-num { text-align: right; font-variant-numeric: tabular-nums; }
    .gp-ok { color: var(--green); font-weight: 600; } .gp-drift { color: var(--yellow); font-weight: 600; }
    .gp-err { color: var(--red); font-weight: 600; } .gp-unk { color: #5b6b80; } .gp-mute { color: var(--muted); }

    /* filter chips */
    .gp-filters { display: flex; gap: 0.4rem; align-items: center; flex-wrap: wrap; margin: 0.2rem 0 0.6rem; }
    .gp-chip { font-size: 0.7rem; padding: 0.22rem 0.6rem; border-radius: 0.35rem;
               border: 1px solid var(--border); color: var(--muted); background: var(--surface);
               cursor: pointer; }
    .gp-chip.on { color: var(--fg); border-color: var(--accent); }
    .gp-search { background: var(--bg); border: 1px solid var(--border); border-radius: 0.4rem;
                 color: var(--fg); padding: 0.28rem 0.55rem; font-size: 0.74rem; min-width: 180px; }

    /* events */
    .gp-ev { display: flex; gap: 0.6rem; padding: 0.32rem 0; border-bottom: 1px solid var(--border); font-size: 0.74rem; }
    .gp-ev .t { color: var(--muted); font-variant-numeric: tabular-nums; white-space: nowrap; }
    .gp-badge { font-size: 0.58rem; font-weight: 700; padding: 0.05rem 0.35rem; border-radius: 0.25rem;
                background: var(--mds-color-bg-warning-tinted); color: var(--yellow); text-transform: uppercase; }

    .gp-placeholder { text-align: center; color: var(--muted); padding: 1.5rem 1rem; font-size: 0.8rem;
                      background: var(--surface); border: 1px dashed var(--border); border-radius: 0.5rem; }
    .gp-placeholder b { display: block; color: var(--fg); margin-bottom: 0.25rem; }

    .gp-btn { height: auto; padding: 0.34rem 0.7rem; font-size: 0.72rem; border-radius: 0.35rem;
              border: 1px solid var(--border); background: var(--mds-color-state-hover); color: var(--fg); cursor: pointer; }
    .gp-btn.accent { border-color: var(--accent); color: var(--accent); background: none; }
    .gp-btn.danger { color: var(--red); }

    /* DEX sub-nav (Overview / Catalogue / Health / Trends) — reuses chip styling */
    .gp-subnav { display: flex; gap: 0.3rem; align-items: center; border-bottom: 1px solid var(--border);
                 padding-bottom: 0.7rem; margin-bottom: 0.6rem; flex-wrap: wrap; }
    .gp-subnav a, .gp-subnav span { font-size: 0.78rem; color: var(--muted); border: 1px solid transparent;
                 border-radius: 0.35rem; padding: 0.22rem 0.6rem; cursor: pointer; }
    .gp-subnav a.on { color: var(--fg); border-color: var(--accent); }
    .gp-subnav span.soon { color: #5b6b80; cursor: default; }
    .gp-subnav .sp { margin-left: auto; font-size: 0.7rem; color: var(--muted); cursor: default; }

    /* DEX catalogue family-card grid (mockup dex-catalogue.html, View 1) */
    .gp-fgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(255px, 1fr));
                gap: 0.7rem; margin-top: 0.6rem; }
    .gp-fcard { background: var(--surface); border: 1px solid var(--border); border-radius: 0.55rem;
                padding: 0.75rem 0.85rem; cursor: pointer; color: var(--fg); display: block;
                transition: border-color 0.12s, transform 0.12s; }
    .gp-fcard:hover { border-color: var(--accent); transform: translateY(-1px); }
    .gp-fcard.quiet { opacity: 0.6; }
    .gp-fcard .fn { color: var(--fg); font-weight: 600; font-size: 0.86rem; display: flex;
                justify-content: space-between; align-items: baseline; gap: 0.4rem; }
    .gp-fcard .fn .cnt { font-size: 0.62rem; color: var(--muted); font-weight: 400; white-space: nowrap; }
    .gp-fcard .fev { font-size: 1.5rem; font-weight: 700; color: var(--fg); line-height: 1; margin-top: 0.5rem; }
    .gp-fcard .fev.bad { color: var(--red); } .gp-fcard .fev.warn { color: var(--yellow); }
    .gp-fcard .fev.ok { color: var(--green); }
    .gp-fcard .fmeta { font-size: 0.62rem; color: var(--muted); }
    .gp-fcard .ftop { font-size: 0.64rem; color: var(--muted); margin-top: 0.45rem;
                border-top: 1px solid var(--border); padding-top: 0.4rem; }
    .gp-fcard .ftop b { color: var(--accent); font-weight: 600; }
)HTM"
    // MSVC caps a single string literal at ~16 KB; the page shell + component CSS
    // outgrew it, so the literal is split here (adjacent literals concatenate).
    R"HTM(
    /* DEX health-score page (mockup dex-health-score.html) */
    .gp-reversal { font-size: 0.72rem; color: var(--accent); background: rgba(0,188,235,0.06);
                border: 1px solid rgba(0,188,235,0.3); border-radius: 0.45rem;
                padding: 0.55rem 0.75rem; margin: 0.9rem 0; }
    .gp-primary { display: flex; gap: 1.1rem; align-items: center; flex-wrap: wrap;
                background: var(--surface); border: 1px solid var(--border);
                border-radius: 0.6rem; padding: 0.85rem 1.05rem; }
    .gp-primary .big { font-size: 2.1rem; font-weight: 700; color: var(--green); line-height: 1; }
    .gp-primary .big.sec { color: var(--fg); font-size: 1.5rem; }
    .gp-primary .lbl { font-size: 0.64rem; color: var(--muted); text-transform: uppercase;
                letter-spacing: 0.05em; }
    .gp-primary .vdiv { width: 1px; align-self: stretch; background: var(--border); }
    .gp-composite { display: flex; gap: 1.4rem; align-items: center; flex-wrap: wrap; margin-top: 0.5rem; }
    .gp-gauge { position: relative; width: 140px; height: 140px; flex-shrink: 0; }
    .gp-gauge .val { position: absolute; inset: 0; display: flex; flex-direction: column;
                align-items: center; justify-content: center; }
    .gp-gauge .val .num { font-size: 2.2rem; font-weight: 700; color: var(--fg); line-height: 1; }
    .gp-gauge .val .band { font-size: 0.66rem; font-weight: 700; text-transform: uppercase;
                letter-spacing: 0.05em; }
    .band-excellent, .band-good { color: var(--green); } .band-fair { color: var(--yellow); }
    .band-poor { color: var(--red); }
    .gp-derived { font-size: 0.6rem; color: var(--muted); border: 1px solid var(--border);
                border-radius: 0.3rem; padding: 0.05rem 0.4rem; display: inline-block; margin-bottom: 0.35rem; }
    .gp-stack { display: flex; height: 26px; border-radius: 5px; overflow: hidden;
                border: 1px solid var(--border); margin-bottom: 0.7rem; }
    .gp-stack > span { display: flex; align-items: center; justify-content: center;
                font-size: 0.56rem; color: #04101f; font-weight: 700; min-width: 0; white-space: nowrap; }
    .gp-ded { display: grid; grid-template-columns: 1.6fr auto 1fr auto; gap: 0.6rem;
                align-items: center; padding: 0.32rem 0; border-bottom: 1px solid var(--border); font-size: 0.78rem; }
    .gp-ded .fam { color: var(--fg); font-weight: 600; }
    .gp-ded .wt { font-size: 0.62rem; text-transform: uppercase; }
    .wt-high { color: var(--red); } .wt-med { color: var(--yellow); } .wt-low { color: var(--muted); }
    .gp-ded .bar { height: 8px; border-radius: 2px; background: var(--red); opacity: 0.8; }
    .gp-ded .pts { text-align: right; font-variant-numeric: tabular-nums; color: var(--red);
                font-weight: 600; min-width: 48px; }
    .gp-subgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 0.55rem; }
    .gp-sscore { background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem;
                padding: 0.55rem 0.7rem; }
    .gp-sscore .nm { font-size: 0.7rem; color: var(--muted); }
    .gp-sscore .vv { font-size: 1.5rem; font-weight: 700; line-height: 1.1; }
    .gp-sscore .ds { font-size: 0.58rem; color: var(--muted); }

    /* DEX trends page (mockup dex-trends.html) */
    .gp-oscards { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0.7rem; }
    .gp-oscard { background: var(--surface); border: 1px solid var(--border); border-radius: 0.55rem;
                padding: 0.85rem 1rem; }
    .gp-oscard.pending { opacity: 0.62; border-style: dashed; }
    .gp-oscard .os { display: flex; align-items: center; gap: 0.5rem; font-size: 0.95rem;
                color: var(--fg); font-weight: 600; }
    .gp-oscard .state { font-size: 0.58rem; border-radius: 0.3rem; padding: 0.05rem 0.4rem;
                border: 1px solid var(--border); }
    .gp-oscard .state.live { color: var(--green); } .gp-oscard .state.limited { color: var(--yellow); }
    .gp-oscard .state.pending { color: var(--muted); }
    .gp-oscard .scope { font-size: 0.62rem; color: var(--muted); margin-top: 0.15rem; }
    .gp-smgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 0.6rem; }
    .gp-sm { background: var(--surface); border: 1px solid var(--border); border-radius: 0.5rem;
                padding: 0.6rem 0.7rem; }
    .gp-sm .smh { display: flex; justify-content: space-between; align-items: baseline; gap: 0.3rem; }
    .gp-sm .smn { font-size: 0.72rem; color: var(--fg); font-weight: 600; }
    .gp-sm .smv { font-size: 0.62rem; color: var(--muted); }
    .gp-heat { display: flex; flex-direction: column; gap: 3px; margin-top: 0.4rem; }
    .gp-heat .hrow { display: flex; align-items: center; gap: 4px; }
    .gp-heat .hlbl { width: 150px; flex-shrink: 0; font-size: 0.62rem; color: var(--muted); text-align: right; }
    .gp-heat .hrow > i { flex: 1; height: 14px; border-radius: 2px; min-width: 6px; }
  </style>
</head>
<body>
  <nav class="nav-bar">
    <a href="/" class="nav-brand">
      <svg class="icon"><use href="/static/icons.svg#home"></use></svg> Yuzu
    </a>
    <a href="/" class="nav-link">Dashboard</a>
    <a href="/instructions" class="nav-link">Instructions</a>
    <a href="/compliance" class="nav-link">Compliance</a>
    <a href="/guardian" class="nav-link active">Guardian</a>
    <a href="/dex" class="nav-link">DEX</a>
    <a href="/network" class="nav-link">Network</a>
    <a href="/tar" class="nav-link">TAR</a>
    <a href="/viz/fleet" class="nav-link">Fleet Viz</a>
    <a href="/settings" class="nav-link" id="nav-settings-link">Settings</a>
    <span class="nav-spacer"></span>
    <span class="nav-user" id="nav-user"></span>
    <button class="nav-logout" hx-post="/logout">Logout</button>
  </nav>
  <div class="context-bar" id="context-bar">
    <span class="context-role-badge" id="role-badge"></span>
    <span class="context-user" id="context-user"></span>
    <span class="context-spacer"></span>
  </div>

  <div class="gp-wrap">
    <div id="guardian-detail"
         hx-get="{{FRAGMENT}}" hx-trigger="load" hx-swap="innerHTML">
      <div class="gp-loading">Loading&hellip;</div>
    </div>
  </div>

  <div id="toast-container" class="toast-container"></div>

  <script>
    /* Generic chip filter for the page's member/device tables. A chip carries
       data-gpf="<group>" + data-gpk="<key>"; rows carry data-gpf="<group>"
       data-gpstate="<key>". "all" matches every row. */
    function gpFilter(btn) {
      var group = btn.getAttribute('data-gpf');
      var key = btn.getAttribute('data-gpk');
      var chips = document.querySelectorAll('.gp-chip[data-gpf="' + group + '"]');
      for (var i = 0; i < chips.length; i++) chips[i].classList.remove('on');
      btn.classList.add('on');
      var rows = document.querySelectorAll('tr[data-gpf="' + group + '"]');
      for (var j = 0; j < rows.length; j++) {
        var st = rows[j].getAttribute('data-gpstate');
        rows[j].style.display = (key === 'all' || st === key) ? '' : 'none';
      }
    }
    /* Free-text row search within a table group (matches data-gpname). */
    function gpSearch(input) {
      var group = input.getAttribute('data-gpf');
      var q = (input.value || '').toLowerCase().trim();
      var rows = document.querySelectorAll('tr[data-gpf="' + group + '"]');
      for (var i = 0; i < rows.length; i++) {
        var name = rows[i].getAttribute('data-gpname') || '';
        rows[i].style.display = (!q || name.indexOf(q) !== -1) ? '' : 'none';
      }
    }

    /* Action buttons (Re-deploy / Delete / Disable): POST via fetch, then reload
       or navigate. A plain onclick — the page CSP allows inline handlers but
       forbids 'unsafe-eval', so htmx's hx-on (which compiles with new Function)
       cannot be used here. */
    function gpAction(method, url, opts) {
      opts = opts || {};
      if (opts.confirm && !window.confirm(opts.confirm)) return;
      fetch(url, { method: method, credentials: 'include' }).then(function (r) {
        // Only navigate/reload on success — a 403 (permission) or 5xx must NOT look
        // like the action applied (gov UP-1 / enterprise BLOCKING). Surface the
        // server message (kept short) as an error toast and stay on the page.
        if (!r.ok) {
          return r.text().then(function (t) {
            showToast(t && t.length > 0 && t.length < 200 ? t : ('Action failed (' + r.status + ')'), 'error');
          });
        }
        if (opts.go) { window.location = opts.go; } else { location.reload(); }
      }).catch(function () { showToast('Network error — the action may not have applied', 'error'); });
    }

    /* Toast system (shared with the dashboard; used by action responses). */
    function showToast(message, level) {
      var c = document.getElementById('toast-container');
      if (!c) return;
      var t = document.createElement('div');
      t.className = 'toast toast-' + (level || 'info');
      t.textContent = message;
      c.appendChild(t);
      if (level !== 'error')
        setTimeout(function () { t.remove(); }, 4000);
    }
    document.body.addEventListener('showToast', function (e) {
      var d = e.detail || {};
      showToast(d.message || 'Done', d.level || 'success');
    });

    /* Populate nav user / role badge, mirroring the dashboard chrome. */
    fetch('/api/me').then(function (r) { return r.json(); }).then(function (d) {
      var nu = document.getElementById('nav-user'); if (nu) nu.textContent = d.username || '';
      var role = d.rbac_role || d.role || '';
      var rb = document.getElementById('role-badge'); if (rb) rb.textContent = role;
      var cu = document.getElementById('context-user'); if (cu) cu.textContent = d.username || '';
      if (d.role !== 'admin' && role !== 'Administrator' && role !== 'PlatformEngineer') {
        var sl = document.getElementById('nav-settings-link'); if (sl) sl.style.display = 'none';
      }
    }).catch(function () {});
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
