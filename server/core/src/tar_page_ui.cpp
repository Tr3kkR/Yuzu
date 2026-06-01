// TAR dashboard page (Phase 15.A — issue #547).
// Hosts the retention-paused source list as the first frame; the
// scope-walking-aware SQL frame (Phase 15.D) and the process-tree viewer
// (Phase 15.H) drop in later. Compiled in its own translation unit to keep
// the long raw string literal away from server.cpp's brace matching.
//
// Design: docs/tar-dashboard.md.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kTarPageHtml = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Yuzu — TAR</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    body { display: flex; flex-direction: column; min-height: 100vh; }
    .tar-content {
      max-width: 1200px;
      margin: 1rem auto;
      padding: 0 1.5rem 2rem 1.5rem;
      width: 100%;
      box-sizing: border-box;
      flex: 1;
    }
    .tar-content h1 {
      font-size: 1.4rem;
      margin: 0.25rem 0 0.5rem 0;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem;
    }
    .tar-subtitle {
      color: var(--mds-color-theme-text-tertiary);
      font-size: 0.85rem;
      margin: 0 0 1.5rem 0;
    }
    .tar-frame {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      margin-bottom: 1.5rem;
      overflow: hidden;
    }
    .tar-frame-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      background: var(--mds-color-state-hover);
    }
    .tar-frame-title {
      font-size: 0.95rem;
      font-weight: 600;
      margin: 0;
    }
    .tar-frame-actions { display: flex; gap: 0.5rem; }
    .tar-frame-actions button {
      padding: 0.35rem 0.85rem;
      font-size: 0.8rem;
      background: var(--accent);
      color: var(--mds-color-text-on-accent);
      border: none;
      border-radius: 0.25rem;
      cursor: pointer;
    }
    .tar-frame-actions button:hover { opacity: 0.85; }
    .tar-frame-actions button.btn-secondary {
      background: var(--surface);
      color: var(--fg);
      border: 1px solid var(--border);
    }
    .tar-frame-body { padding: 1rem; }
    .tar-frame-body table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    .tar-frame-body th {
      text-align: left;
      padding: 0.5rem 0.75rem;
      border-bottom: 1px solid var(--border);
      color: var(--mds-color-theme-text-tertiary);
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .tar-frame-body td {
      padding: 0.5rem 0.75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .tar-frame-body tr:last-child td { border-bottom: none; }
    .tar-frame-body tr:hover { background: var(--mds-color-state-hover); }
    .tar-frame-body .source-pill {
      display: inline-block;
      padding: 0.1rem 0.5rem;
      font-size: 0.7rem;
      font-weight: 600;
      background: var(--mds-color-bg-warning-tinted);
      color: var(--mds-color-indicator-warning-bright);
      border-radius: 0.75rem;
    }
    .tar-frame-body .placeholder {
      padding: 2rem 0;
      text-align: center;
      color: var(--mds-color-theme-text-tertiary);
    }
    .tar-frame-body .empty-state {
      padding: 2.5rem 0;
      text-align: center;
      color: var(--mds-color-theme-text-tertiary);
      font-size: 0.9rem;
    }
    .tar-frame-body .empty-state strong { color: var(--green); }
    .tar-frame-coming-soon {
      padding: 2rem;
      text-align: center;
      color: var(--mds-color-theme-text-tertiary);
      font-size: 0.85rem;
      background: var(--mds-color-state-hover);
      border: 1px dashed var(--border);
      border-radius: 0.25rem;
      margin: 0.5rem;
    }
    .tar-frame-coming-soon code {
      background: var(--mds-color-state-hover);
      padding: 0.1rem 0.4rem;
      border-radius: 0.25rem;
      font-size: 0.8rem;
    }
    .tar-row-error { color: var(--mds-color-theme-indicator-error); }
    .tar-row-error td { font-style: italic; }

    /* Scope chip (design §8.3) — reusable header for query frames. */
    .scope-chip-row {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin-bottom: 0.75rem;
      flex-wrap: wrap;
    }
    .scope-chip-label {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--mds-color-theme-text-tertiary);
      font-weight: 600;
    }
    .scope-chip-select {
      background: var(--surface);
      color: var(--fg);
      border: 1px solid var(--border);
      border-radius: 0.25rem;
      padding: 0.3rem 0.5rem;
      font-size: 0.8rem;
      max-width: 24rem;
    }
    .scope-chip-meta {
      font-size: 0.75rem;
      color: var(--mds-color-theme-text-tertiary);
    }
    .tar-sql-textarea {
      width: 100%;
      box-sizing: border-box;
      background: var(--mds-color-state-hover);
      color: var(--fg);
      border: 1px solid var(--border);
      border-radius: 0.25rem;
      padding: 0.6rem;
      font-family: var(--mono, monospace);
      font-size: 0.8rem;
      resize: vertical;
    }
    .tar-sql-controls {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin-top: 0.6rem;
      flex-wrap: wrap;
    }
    .tar-sql-name {
      flex: 1 1 16rem;
      min-width: 12rem;
      background: var(--surface);
      color: var(--fg);
      border: 1px solid var(--border);
      border-radius: 0.25rem;
      padding: 0.35rem 0.5rem;
      font-size: 0.8rem;
    }
    .tar-sql-empty {
      font-size: 0.75rem;
      color: var(--mds-color-theme-text-tertiary);
      display: flex;
      align-items: center;
      gap: 0.3rem;
    }
    .tar-sql-controls button {
      padding: 0.4rem 0.9rem;
      font-size: 0.8rem;
      background: var(--accent);
      color: var(--mds-color-text-on-accent);
      border: none;
      border-radius: 0.25rem;
      cursor: pointer;
    }
    .tar-sql-controls button:disabled { opacity: 0.5; cursor: default; }
    .tar-sql-result {
      margin-top: 0.75rem;
      font-size: 0.82rem;
      color: var(--mds-color-theme-text-tertiary);
    }
    .tar-sql-result a { color: var(--accent); }
    .tar-sql-result code {
      background: var(--mds-color-state-hover);
      padding: 0.1rem 0.35rem;
      border-radius: 0.25rem;
    }
    .tar-sql-result.error { color: var(--mds-color-theme-indicator-error); }
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
    <a href="/tar" class="nav-link active">TAR</a>
    <a href="/viz/fleet" class="nav-link">Fleet Viz</a>
    <a href="/result-sets" class="nav-link">Result Sets</a>
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

  <div class="tar-content">
    <h1>TAR &mdash; Timeline Activity Record</h1>
    <p class="tar-subtitle">
      Forensic + inventory data warehouse on each agent. Disable a
      collector to freeze its data for analysis; re-enable when finished.
    </p>

    <!-- ── Retention-paused sources (Phase 15.A) ─────────────────────── -->
    <div class="tar-frame" id="frame-retention-paused">
      <div class="tar-frame-header">
        <h2 class="tar-frame-title">Retention-paused sources</h2>
        <div class="tar-frame-actions">
          <button class="btn-secondary"
                  hx-post="/fragments/tar/retention-paused/scan"
                  hx-target="#retention-paused-body"
                  hx-swap="innerHTML">
            Scan fleet
          </button>
          <button hx-get="/fragments/tar/retention-paused"
                  hx-target="#retention-paused-body"
                  hx-swap="innerHTML">
            Refresh
          </button>
        </div>
      </div>
      <div class="tar-frame-body" id="retention-paused-body"
           hx-get="/fragments/tar/retention-paused"
           hx-trigger="load"
           hx-swap="innerHTML">
        <div class="placeholder">Loading paused sources&hellip;</div>
      </div>
    </div>

    <!-- ── Ad-hoc TAR SQL frame (Phase 15.D — scope walking) ────────── -->
    <div class="tar-frame" id="frame-tar-sql">
      <div class="tar-frame-header">
        <h2 class="tar-frame-title">Ad-hoc TAR SQL</h2>
        <div class="tar-frame-actions">
          <button class="btn-secondary" id="tar-sql-refresh-scopes"
                  title="Reload your result sets">Refresh scopes</button>
        </div>
      </div>
      <div class="tar-frame-body">
        <!-- Scope chip (design §8.3): pick the candidate scope this query
             narrows. Submitting creates a NEW result set parented at the
             selected set. Standard scopes (__all__) carry no parent. -->
        <div class="scope-chip-row">
          <label class="scope-chip-label" for="tar-sql-scope">Scope</label>
          <select id="tar-sql-scope" class="scope-chip-select">
            <option value="__all__">__all__ — entire fleet</option>
          </select>
          <span class="scope-chip-meta" id="tar-sql-scope-meta"></span>
        </div>
        <textarea id="tar-sql-text" class="tar-sql-textarea" rows="4" spellcheck="false"
                  placeholder="SELECT DISTINCT pid FROM process_live WHERE name = 'chrome.exe'"></textarea>
        <div class="tar-sql-controls">
          <input type="text" id="tar-sql-name" class="tar-sql-name"
                 placeholder="Name (optional) e.g. windows-chrome-suspects" maxlength="120">
          <label class="tar-sql-empty">
            <input type="checkbox" id="tar-sql-include-empty"> include responders with 0 rows
          </label>
          <button id="tar-sql-run">Run &amp; create result set</button>
        </div>
        <div class="tar-sql-result" id="tar-sql-result"></div>
      </div>
    </div>

    <!-- ── Process tree viewer (Phase 15.H — pending) ───────────────── -->
    <div class="tar-frame" id="frame-process-tree">
      <div class="tar-frame-header">
        <h2 class="tar-frame-title">Process tree viewer</h2>
      </div>
      <div class="tar-frame-body">
        <div class="tar-frame-coming-soon">
          Reconstructed from <code>process_live</code> seed + events.
          Lands in
          <a href="https://github.com/Tr3kkR/Yuzu/issues/554" target="_blank">issue #554</a>
          (Phase 15.H), gated on agent service-install hardening.
        </div>
      </div>
    </div>
  </div>

  <div id="toast-container" class="toast-container"></div>

)HTM"
// Split here (not a content boundary): MSVC caps a single string literal at
// 16380 chars (C2026) and this page exceeds it. Adjacent raw-string literals
// are concatenated by the compiler, so the rendered HTML is byte-identical.
R"HTM(<script>
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

// ── Scope-walking SQL frame (Phase 15.D) ─────────────────────────────────
// Drives the scope chip + ad-hoc TAR SQL against the REST result-set API.
// Selecting a scope picks the candidate set; running the query dispatches
// tar.sql to that scope and creates a NEW result set parented at it, then
// polls until the async maintenance thread materialises membership.
(function() {
  var scopeSel  = document.getElementById('tar-sql-scope');
  var scopeMeta = document.getElementById('tar-sql-scope-meta');
  var sqlText   = document.getElementById('tar-sql-text');
  var nameInput = document.getElementById('tar-sql-name');
  var emptyChk  = document.getElementById('tar-sql-include-empty');
  var runBtn    = document.getElementById('tar-sql-run');
  var resultBox = document.getElementById('tar-sql-result');
  var refreshBtn= document.getElementById('tar-sql-refresh-scopes');
  if (!scopeSel || !runBtn) return;

  // id -> {name, device_count, status} for the meta line.
  var scopeIndex = {};

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function(c) {
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c];
    });
  }

  function renderMeta() {
    var v = scopeSel.value;
    if (v === '__all__') { scopeMeta.textContent = 'entire fleet — no parent'; return; }
    var s = scopeIndex[v];
    if (!s) { scopeMeta.textContent = ''; return; }
    var bits = [s.device_count + ' devices'];
    if (s.status && s.status !== 'materialized') bits.push(s.status);
    scopeMeta.textContent = bits.join(' · ');
  }

  function loadScopes() {
    fetch('/api/v1/result-sets?limit=200').then(function(r){return r.json();}).then(function(j){
      var sets = (j.data && j.data.result_sets) || [];
      var keep = scopeSel.value;
      scopeIndex = {};
      while (scopeSel.options.length > 1) scopeSel.remove(1);
      sets.forEach(function(s){
        scopeIndex[s.id] = s;
        var label = (s.name ? s.name : s.id) + ' — ' + s.device_count + ' devices'
                  + (s.status && s.status !== 'materialized' ? ' (' + s.status + ')' : '');
        var opt = document.createElement('option');
        opt.value = s.id; opt.textContent = label;
        scopeSel.appendChild(opt);
      });
      if (keep && (keep === '__all__' || scopeIndex[keep])) scopeSel.value = keep;
      renderMeta();
    }).catch(function(){ /* leave __all__ only */ });
  }

  // Poll a freshly-created pending set until membership materialises.
  function pollSet(id, name, tries) {
    fetch('/api/v1/result-sets/' + encodeURIComponent(id)).then(function(r){return r.json();})
      .then(function(j){
        var s = j.data || {};
        if (s.status === 'pending' && tries > 0) {
          setTimeout(function(){ pollSet(id, name, tries - 1); }, 2000);
          return;
        }
        if (s.status === 'failed') {
          resultBox.className = 'tar-sql-result error';
          resultBox.innerHTML = 'Result set <code>' + esc(id) + '</code> failed to materialise.';
        } else if (s.status === 'pending') {
          resultBox.className = 'tar-sql-result';
          resultBox.innerHTML = 'Result set <code>' + esc(id) + '</code> still pending — '
            + '<a href="/result-sets">view in Result Sets</a>.';
        } else {
          resultBox.className = 'tar-sql-result';
          resultBox.innerHTML = 'Created <code>' + esc(name || id) + '</code> — <strong>'
            + esc(s.device_count) + '</strong> device(s). '
            + 'Copy scope token <code>from_result_set:' + esc(id) + '</code> · '
            + '<a href="/result-sets">open</a>';
          loadScopes();
        }
        runBtn.disabled = false;
      }).catch(function(){ runBtn.disabled = false; });
  }

  function run() {
    var sql = sqlText.value.trim();
    if (!sql) { showToast('Enter a SQL query', 'warning'); return; }
    var body = { sql: sql, include_empty: !!emptyChk.checked };
    var nm = nameInput.value.trim();
    if (nm) body.name = nm;
    if (scopeSel.value && scopeSel.value !== '__all__') body.parent_id = scopeSel.value;
    runBtn.disabled = true;
    resultBox.className = 'tar-sql-result';
    resultBox.textContent = 'Dispatching to agents…';
    fetch('/api/v1/result-sets/from-tar-query', {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
    }).then(function(r){ return r.json().then(function(j){ return {status:r.status, body:j}; }); })
      .then(function(res){
        if (res.status === 202 && res.body.data) {
          var s = res.body.data;
          resultBox.innerHTML = 'Dispatched (execution <code>' + esc(s.source_execution_id)
            + '</code>) — awaiting responses…';
          pollSet(s.id, s.name, 150);
        } else {
          var msg = (res.body.error && (res.body.error.message || res.body.error)) || 'request failed';
          resultBox.className = 'tar-sql-result error';
          resultBox.textContent = msg;
          runBtn.disabled = false;
        }
      }).catch(function(){
        resultBox.className = 'tar-sql-result error';
        resultBox.textContent = 'network error';
        runBtn.disabled = false;
      });
  }

  scopeSel.addEventListener('change', renderMeta);
  runBtn.addEventListener('click', run);
  if (refreshBtn) refreshBtn.addEventListener('click', loadScopes);
  loadScopes();
})();
</script>
</body></html>
)HTM";
// NOLINTEND(cert-err58-cpp)
