// Guardian dashboard page — Guaranteed State enforcement across the fleet.
//
// Mirrors the compliance_ui.cpp pattern: the page shell is server-rendered
// HTML; all interactive data is loaded as HTMX fragments from
// /fragments/guardian/* (see guardian_routes.cpp).
//
// Product UI — HTMX, server-rendered, dark-theme only. Do NOT apply the
// `frontend-design` plugin here (that is marketing-only). Follow the existing
// dashboard conventions.
//
// The page HTML is emitted as several adjacent raw-string literals that the
// compiler concatenates: MSVC caps a single string literal at ~16 KB (C2026),
// and the whole page exceeds that, so it is split at natural boundaries.
//
// Vocabulary note (contract G5): the UI uses the *target* ubiquitous language
// — Guard / Baseline / Spark / Assertion — while the code, REST surface
// (/api/v1/guaranteed-state/*) and RBAC securable ("GuaranteedState") still
// carry the legacy `rule`/`GuaranteedState` naming until the dedicated rename
// PR. See docs/guardian-mvp-contract.md §3, §8.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kGuardianHtml =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Guardian</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    body { min-height: 100vh; }

    /* ── Content ───────────────────────────────────────────── */
    .content {
      max-width: 1200px; margin: 1.5rem auto; padding: 0 1.5rem;
    }

    /* ── Page header ──────────────────────────────────────── */
    .page-header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 1.5rem; padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border);
    }
    .page-header h1 { font-size: 1.1rem; font-weight: 700; }
    .page-header .subtitle { font-size: 0.75rem; color: var(--muted); margin-top: 0.15rem; }
    .page-header .header-actions { display: flex; gap: 0.5rem; align-items: center; }

    /* ── Section cards ─────────────────────────────────────── */
    .section {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 0.5rem; margin-bottom: 1.5rem; overflow: hidden;
    }
    .section-header {
      padding: 0.75rem 1rem; font-size: 0.85rem; font-weight: 600;
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 0.5rem;
    }
    .section-body { padding: 1rem; }

    /* ── Summary stat cards ────────────────────────────────── */
    .stat-cards { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: stretch; }
    .stat-card {
      flex: 1 1 110px; min-width: 96px;
      background: var(--bg); border: 1px solid var(--border);
      border-radius: 0.5rem; padding: 0.75rem 1rem; text-align: center;
    }
    .stat-num { font-size: 1.6rem; font-weight: 700; line-height: 1; }
    .stat-label {
      font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.05em;
      color: var(--muted); margin-top: 0.35rem;
    }
    .stat-num.good { color: var(--green); }
    .stat-num.warn { color: var(--yellow); }
    .stat-num.bad  { color: var(--red); }
    .stat-num.info { color: var(--accent); }
    .stat-num.mute { color: var(--muted); }

    /* Fleet worst-of badge — the single most-severe state present. */
    .worst-badge {
      display: inline-flex; align-items: center; gap: 0.4rem;
      padding: 0.25rem 0.7rem; border-radius: 1rem;
      font-size: 0.75rem; font-weight: 700;
    }
    .worst-good { background: var(--mds-color-bg-success-tinted); color: var(--green); }
    .worst-warn { background: var(--mds-color-bg-warning-tinted); color: var(--yellow); }
    .worst-bad  { background: var(--mds-color-bg-error-tinted);   color: var(--red); }

    /* ── Guard status badges (full taxonomy) ───────────────── */
    .gs-badge {
      display: inline-block; padding: 0.1rem 0.5rem;
      border-radius: 1rem; font-size: 0.68rem; font-weight: 600;
      white-space: nowrap;
    }
    .gs-compliant         { background: var(--mds-color-bg-success-tinted); color: var(--green); }
    .gs-drifted           { background: var(--mds-color-bg-warning-tinted); color: var(--yellow); }
    .gs-remediation_failed{ background: var(--mds-color-bg-error-tinted);   color: var(--red); }
    .gs-errored           { background: var(--mds-color-bg-error-tinted);   color: var(--red); }
    .gs-exempt            { background: var(--mds-color-state-selected);    color: var(--muted); }
    .gs-stale             { background: var(--mds-color-state-hover);       color: var(--muted); border: 1px dashed var(--border); }

    /* guard_healthy signal — distinct from compliance state. */
    .health-ok   { color: var(--green); }
    .health-bad  { color: var(--red); }
    .health-dot  { font-size: 0.7rem; }

    /* ── View switcher (fleet / guard / agent / mgroup / baseline) ── */
    .view-switch { display: flex; gap: 0; flex-wrap: wrap; margin-bottom: 1rem; }
    .view-btn {
      padding: 0.35rem 0.8rem; font-size: 0.75rem; cursor: pointer;
      background: var(--surface); color: var(--muted);
      border: 1px solid var(--border); border-right: none;
    }
    .view-btn:first-child { border-radius: 0.4rem 0 0 0.4rem; }
    .view-btn:last-child  { border-radius: 0 0.4rem 0.4rem 0; border-right: 1px solid var(--border); }
    .view-btn.active { background: var(--mds-color-state-selected); color: var(--fg); font-weight: 600; }
    .view-btn:hover  { color: var(--fg); }

    /* ── Two-column grid: guards | events ──────────────────── */
    .gs-grid {
      display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;
    }
    @media (max-width: 900px) { .gs-grid { grid-template-columns: 1fr; } }

    /* ── Guard list ────────────────────────────────────────── */
    .guard-list { display: flex; flex-direction: column; gap: 0.5rem; }
    .guard-item {
      border: 1px solid var(--border); border-radius: 0.4rem;
      padding: 0.6rem 0.75rem; cursor: pointer; background: var(--bg);
    }
    .guard-item:hover { background: var(--mds-color-state-hover); }
    .guard-item-top { display: flex; align-items: center; gap: 0.5rem; }
    .guard-name { font-weight: 600; font-size: 0.82rem; }
    .guard-os {
      font-size: 0.6rem; font-family: var(--mono); color: var(--muted);
      border: 1px solid var(--border); border-radius: 0.25rem; padding: 0 0.25rem;
    }
    .guard-meta { font-size: 0.72rem; color: var(--muted); margin-top: 0.3rem;
                  display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; }

    /* ── Event timeline ────────────────────────────────────── */
    .event-list { display: flex; flex-direction: column; }
    .event-item {
      padding: 0.5rem 0; border-bottom: 1px solid var(--border);
      font-size: 0.78rem;
    }
    .event-item:last-child { border-bottom: none; }
    .event-top { display: flex; align-items: center; gap: 0.5rem; }
    .event-time { font-family: var(--mono); font-size: 0.7rem; color: var(--muted); }
    .event-type {
      font-size: 0.62rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.04em; padding: 0.05rem 0.4rem; border-radius: 0.25rem;
    }
    .et-drift_detected      { background: var(--mds-color-bg-warning-tinted); color: var(--yellow); }
    .et-drift_remediated    { background: var(--mds-color-bg-success-tinted); color: var(--green); }
    .et-remediation_failed  { background: var(--mds-color-bg-error-tinted);   color: var(--red); }
    .et-guard_armed         { background: var(--mds-color-state-selected);    color: var(--accent); }
    .et-guard_unhealthy     { background: var(--mds-color-bg-error-tinted);   color: var(--red); }
    .et-resilience_escalated{ background: var(--mds-color-bg-warning-tinted); color: var(--yellow); }
    .et-generic             { background: var(--mds-color-state-hover);       color: var(--muted); }
    .event-detail { color: var(--muted); margin-top: 0.2rem; }
    .event-detail strong { color: var(--fg); font-weight: 500; }

    /* ── Baseline cards ────────────────────────────────────── */
    .baseline-card {
      border: 1px solid var(--border); border-radius: 0.4rem;
      padding: 0.75rem; margin-bottom: 0.6rem; background: var(--bg);
    }
    .baseline-top { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
    .baseline-name { font-weight: 600; font-size: 0.85rem; }
    .baseline-scope { font-size: 0.72rem; color: var(--muted); font-family: var(--mono); margin-top: 0.25rem; }
    .lifecycle-draft    { color: var(--muted); }
    .lifecycle-deployed { color: var(--green); }

    /* ── Detail panel ──────────────────────────────────────── */
    .detail-panel {
      margin-top: 0.5rem; padding: 1rem;
      background: var(--bg); border: 1px solid var(--border);
      border-radius: 0.5rem;
    }
    .detail-panel h3 { font-size: 0.9rem; margin-bottom: 0.5rem;
                       display: flex; align-items: center; gap: 0.5rem; }
    .kv { display: grid; grid-template-columns: 130px 1fr; gap: 0.3rem 1rem;
          font-size: 0.78rem; margin-bottom: 0.75rem; }
    .kv .k { color: var(--muted); }
    .detail-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
    .detail-table th {
      text-align: left; padding: 0.35rem 0.5rem;
      border-bottom: 2px solid var(--border); color: var(--muted);
      font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;
    }
    .detail-table td { padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border); }
    .detail-table tr:hover { background: var(--mds-color-state-hover); }
    pre.yaml {
      background: var(--bg); border: 1px solid var(--border); border-radius: 0.4rem;
      padding: 0.75rem; font-family: var(--mono); font-size: 0.72rem;
      overflow-x: auto; white-space: pre; color: var(--fg);
    }

    /* ── Forms (create Guard / Baseline, push) ─────────────── */
    .gs-form label { display: block; font-size: 0.72rem; color: var(--muted);
                     margin: 0.6rem 0 0.2rem; text-transform: uppercase; letter-spacing: 0.04em; }
    .gs-form input, .gs-form select, .gs-form textarea {
      width: 100%; background: var(--bg); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.3rem; padding: 0.4rem 0.5rem;
      font-size: 0.8rem; font-family: inherit;
    }
    .gs-form textarea { font-family: var(--mono); min-height: 80px; }
    .form-row { display: flex; gap: 0.75rem; }
    .form-row > div { flex: 1; }
    .form-actions { margin-top: 1rem; display: flex; gap: 0.5rem; }

    /* ── Push panel ────────────────────────────────────────── */
    .push-row { display: flex; gap: 0.75rem; align-items: flex-end; flex-wrap: wrap; }
    .push-row > div { flex: 1; min-width: 220px; }

    /* ── Empty / loading states ────────────────────────────── */
    .empty-state { text-align: center; padding: 2rem 1rem; color: var(--subtle); font-size: 0.85rem; }
    .mock-note {
      font-size: 0.68rem; color: var(--subtle); font-style: italic;
      margin-top: 0.5rem;
    }

    /* ── Buttons ───────────────────────────────────────────── */
    .btn { height: auto; padding: 0.3rem 0.8rem; font-size: 0.75rem; border: none; cursor: pointer; }
    .btn-secondary { background: var(--surface); color: var(--fg); border: 1px solid var(--border); }
    .btn-sm { padding: 0.2rem 0.5rem; font-size: 0.7rem; }

    .htmx-indicator { display: none; color: var(--muted); font-size: 0.75rem; }
    .htmx-request .htmx-indicator, .htmx-request.htmx-indicator { display: inline; }
  </style>
)HTM"
    // Split point 1 (MSVC C2026 — see file header). Adjacent literals concat.
    R"HTM(</head>
<body>

  <nav class="nav-bar">
    <a href="/" class="nav-brand">
      <svg class="icon"><use href="/static/icons.svg#home"></use></svg> Yuzu
    </a>
    <a href="/" class="nav-link">Dashboard</a>
    <a href="/instructions" class="nav-link">Instructions</a>
    <a href="/compliance" class="nav-link">Compliance</a>
    <a href="/guardian" class="nav-link active">Guardian</a>
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
    <button class="context-bell" title="Notifications">
      <svg class="icon"><use href="/static/icons.svg#bell"></use></svg>
    </button>
  </div>

  <div class="content">

    <div class="page-header">
      <div>
        <h1>Guardian</h1>
        <div class="subtitle">Guaranteed State enforcement &mdash; live status, Guards &amp; Baselines</div>
      </div>
      <div class="header-actions">
        <button class="btn btn-secondary"
                hx-get="/fragments/guardian/guard-form"
                hx-target="#guardian-detail" hx-swap="innerHTML">
          + New Guard
        </button>
        <button class="btn btn-secondary"
                hx-get="/fragments/guardian/baseline-form"
                hx-target="#guardian-detail" hx-swap="innerHTML">
          + New Baseline
        </button>
        <button class="btn btn-secondary"
                hx-get="/fragments/guardian/status?view=fleet"
                hx-target="#guardian-status" hx-swap="innerHTML">
          <svg class="icon" style="width:14px;height:14px"><use href="/static/icons.svg#refresh-cw"></use></svg>
          Refresh
        </button>
      </div>
    </div>

    <!-- ── Status overview (view-switchable rollup) ─────────── -->
    <div class="section">
      <div class="section-header">
        <svg class="icon"><use href="/static/icons.svg#shield"></use></svg>
        Fleet Status
        <span class="htmx-indicator" style="margin-left:auto">Refreshing&hellip;</span>
      </div>
      <div class="section-body">
        <div class="view-switch">
          <button class="view-btn active" hx-get="/fragments/guardian/status?view=fleet"
                  hx-target="#guardian-status" hx-swap="innerHTML"
                  onclick="gsSetActive(this)">Fleet</button>
          <button class="view-btn" hx-get="/fragments/guardian/status?view=guard"
                  hx-target="#guardian-status" hx-swap="innerHTML"
                  onclick="gsSetActive(this)">By Guard</button>
          <button class="view-btn" hx-get="/fragments/guardian/status?view=agent"
                  hx-target="#guardian-status" hx-swap="innerHTML"
                  onclick="gsSetActive(this)">By Agent</button>
          <button class="view-btn" hx-get="/fragments/guardian/status?view=mgroup"
                  hx-target="#guardian-status" hx-swap="innerHTML"
                  onclick="gsSetActive(this)">By Management Group</button>
          <button class="view-btn" hx-get="/fragments/guardian/status?view=baseline"
                  hx-target="#guardian-status" hx-swap="innerHTML"
                  onclick="gsSetActive(this)">By Baseline</button>
        </div>
        <div id="guardian-status"
             hx-get="/fragments/guardian/status?view=fleet"
             hx-trigger="load" hx-swap="innerHTML">
          <div class="empty-state">Loading status&hellip;</div>
        </div>
      </div>
    </div>

    <!-- ── Guards | Events ──────────────────────────────────── -->
    <div class="gs-grid">
      <div class="section">
        <div class="section-header">
          <svg class="icon"><use href="/static/icons.svg#list"></use></svg>
          Guards
        </div>
        <div class="section-body">
          <div id="guardian-guards"
               hx-get="/fragments/guardian/guards"
               hx-trigger="load" hx-swap="innerHTML">
            <div class="empty-state">Loading guards&hellip;</div>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <svg class="icon"><use href="/static/icons.svg#activity"></use></svg>
          Recent Events
          <span class="htmx-indicator" style="margin-left:auto">&middot;&middot;&middot;</span>
        </div>
        <div class="section-body">
          <div id="guardian-events"
               hx-get="/fragments/guardian/events"
               hx-trigger="load, every 5s" hx-swap="innerHTML">
            <div class="empty-state">Loading events&hellip;</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ── Baselines ────────────────────────────────────────── -->
    <div class="section">
      <div class="section-header">
        <svg class="icon"><use href="/static/icons.svg#layers"></use></svg>
        Baselines
        <span style="margin-left:auto;font-size:0.7rem;font-weight:400;color:var(--muted)">
          deploy is Baseline-level
        </span>
      </div>
      <div class="section-body">
        <div id="guardian-baselines"
             hx-get="/fragments/guardian/baselines"
             hx-trigger="load" hx-swap="innerHTML">
          <div class="empty-state">Loading baselines&hellip;</div>
        </div>
      </div>
    </div>

    <!-- ── Detail drill-in (guard / baseline / forms) ───────── -->
    <div class="section">
      <div class="section-header">
        <svg class="icon"><use href="/static/icons.svg#info"></use></svg>
        Detail
      </div>
      <div class="section-body">
        <div id="guardian-detail">
          <div class="empty-state">
            Select a Guard or Baseline above, or use <strong>+ New Guard</strong> /
            <strong>+ New Baseline</strong> to compose one.
          </div>
        </div>
      </div>
    </div>

  </div>

  <div id="toast-container" class="toast-container"></div>
)HTM"
    // Split point 2 (MSVC C2026 — see file header). Adjacent literals concat.
    R"HTM(
  <script>
    /* ── View switcher active-state toggle ─────────────────── */
    function gsSetActive(btn) {
      var btns = btn.parentNode.querySelectorAll('.view-btn');
      for (var i = 0; i < btns.length; i++) btns[i].classList.remove('active');
      btn.classList.add('active');
    }

    /* ── Toast notification system ─────────────────────────── */
    function showToast(message, level) {
      var c = document.getElementById('toast-container');
      if (!c) return;
      var t = document.createElement('div');
      t.className = 'toast toast-' + (level || 'info');
      t.textContent = message;
      var close = document.createElement('button');
      close.textContent = '×';
      close.style.cssText = 'background:none;border:none;color:var(--muted);cursor:pointer;margin-left:auto;font-size:1.2rem;padding:0 0 0 var(--sp-3);';
      close.onclick = function() { t.remove(); };
      t.style.display = 'flex';
      t.style.alignItems = 'center';
      t.appendChild(close);
      c.appendChild(t);
      if (level !== 'error') {
        setTimeout(function() { t.style.opacity = '0'; t.style.transition = 'opacity 0.3s'; setTimeout(function() { t.remove(); }, 300); }, level === 'warning' ? 8000 : 4000);
      }
    }
    document.body.addEventListener('showToast', function(e) {
      var d = e.detail || {};
      showToast(d.message || 'Done', d.level || 'success');
    });

    /* ── Populate nav bar + context bar ─────────────────────── */
    fetch('/api/me').then(function(r){return r.json()}).then(function(d){
      document.getElementById('nav-user').textContent = d.username;
      var role = d.rbac_role || d.role;
      document.getElementById('role-badge').textContent = role;
      document.getElementById('context-user').textContent = d.username;
      document.body.setAttribute('data-role', role);
      if(d.role !== 'admin' && role !== 'Administrator' && role !== 'PlatformEngineer') {
        var sl = document.getElementById('nav-settings-link');
        if(sl) sl.style.display = 'none';
      }
    });
    /* Ctrl+K / Cmd+K — navigate to dashboard command palette */
    document.addEventListener('keydown', function(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        window.location.href = '/?palette=1';
      }
    });
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
