// Instruction management page with YAML authoring UI.
// HTMX-driven with split-panel editor: textarea (left) + server-rendered
// syntax-highlighted preview (right). The authoring panel (New/Edit) is
// only shown to users with the PlatformEngineer or Administrator role.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kInstructionPageHtml = R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Instructions</title>
<link rel="stylesheet" href="/static/yuzu.css">
<script src="/static/htmx.js"></script>
<style>
body{padding:0}
a{color:var(--accent)}h1{border-bottom:1px solid var(--border);padding-bottom:.5rem}
.tabs{display:flex;gap:.5rem;margin-bottom:1rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}
.tab{padding:.4rem 1rem;cursor:pointer;border:1px solid transparent;border-radius:6px 6px 0 0;color:var(--muted)}
.tab.active,.tab:hover{color:var(--fg);border-color:var(--border);background:var(--surface)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--border);font-size:.8rem}
th{color:var(--muted);font-weight:600}
.empty-state{color:var(--muted);text-align:center;padding:2rem}
.status-badge{display:inline-block;padding:.1rem .5rem;border-radius:1rem;font-size:.7rem;font-weight:600}
.status-pending{background:var(--yellow);color: var(--mds-color-theme-background-canvas)}
.status-running{background:var(--mds-color-theme-accent-primary-active);color:var(--mds-color-text-on-accent)}
.status-completed{background:var(--green);color:var(--mds-color-text-on-accent)}
.status-cancelled{background:var(--subtle);color:var(--mds-color-text-on-accent)}
.status-failed{background:var(--red);color:var(--mds-color-text-on-accent)}
.status-approved{background:var(--green);color:var(--mds-color-text-on-accent)}
.status-rejected{background:var(--red);color:var(--mds-color-text-on-accent)}
/* Instruction-page button overrides (smaller, denser) */
.btn{height:auto;padding:.3rem .8rem;font-size:.75rem;margin-right:.3rem}
.btn-primary{background:var(--green);color:var(--mds-color-text-on-accent)}
.btn-secondary{background:var(--surface);color:var(--fg);border:1px solid var(--border)}
.btn-danger{background:var(--red);color:var(--mds-color-text-on-accent)}
.btn-sm{padding:.2rem .5rem;font-size:.7rem}
.progress-bar{width:80px;height:8px;background:var(--border);border-radius:4px;display:inline-block;vertical-align:middle}
.progress-fill{height:100%;background:var(--green);border-radius:4px}
code{background:var(--surface);padding:.1rem .3rem;border-radius:4px;font-size:.75rem}
.toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:.8rem}
.role-badge{display:inline-block;padding:.1rem .4rem;border-radius:4px;font-size:.65rem;
  font-weight:600;background:var(--mds-color-theme-accent-primary-active);color:var(--mds-color-text-on-accent);margin-left:.5rem;vertical-align:middle}
/* Editor panel */
.editor-panel{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.2rem;margin-bottom:1rem;display:none}
.editor-panel.active{display:block}
.editor-tabs{display:flex;gap:.3rem;margin-bottom:1rem}
.editor-tab{padding:.3rem .8rem;cursor:pointer;border:1px solid var(--border);border-radius:4px;
  font-size:.75rem;color:var(--muted);background:transparent}
.editor-tab.active{color:var(--fg);background:var(--border)}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:.8rem}
.form-group{display:flex;flex-direction:column;gap:.2rem}
.form-group.full{grid-column:1/-1}
label{font-size:.75rem;color:var(--muted);font-weight:600}
input,select,textarea{background:var(--bg);border:1px solid var(--border);border-radius:4px;
  padding:.4rem .6rem;color:var(--fg);font-size:.8rem;font-family:inherit}
textarea{font-family:var(--font-mono);min-height:300px;resize:vertical;tab-size:2}
input:focus,select:focus,textarea:focus{border-color:var(--accent);outline:none}
/* Syntax token colors — GitHub-dark-inspired */
.yk{color: var(--mds-color-indicator-info-bright)}                     /* YAML key */
.yv{color:var(--mds-color-indicator-info-bright)} /* YAML string value */
.yc{color: var(--mds-color-theme-text-tertiary);font-style:italic}   /* comment */
.ya{color: var(--mds-color-indicator-special)}                     /* apiVersion / kind (schema keywords) */
.yt-q{color: var(--mds-color-indicator-success-bright)}                   /* type: question — green (safe, read-only) */
.yt-a{color: var(--mds-color-indicator-attention);font-weight:700}   /* type: action — orange bold (privileged, modifying) */
.yap{color: var(--mds-color-indicator-error-bright);font-weight:700}    /* approval: always — red bold (requires sign-off) */
.yap-auto{color: var(--mds-color-indicator-success-bright)}              /* approval: auto — green (no gate) */
.ycc{color: var(--mds-color-theme-indicator-warning)}                    /* concurrency mode — amber */
.yn{color: var(--mds-color-indicator-info-bright)}                     /* numeric values */
.yb{color: var(--mds-color-indicator-error-bright)}                     /* boolean values */
.yd{color: var(--mds-color-theme-text-tertiary)}                     /* dashes (list markers) */
/* Legend */
.yaml-legend{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:.5rem;font-size:.7rem}
.yaml-legend span{display:flex;align-items:center;gap:.3rem}
.yaml-legend .swatch{width:10px;height:10px;border-radius:2px;display:inline-block}
.form-actions{margin-top:1rem;display:flex;gap:.5rem}
/* alert overrides (shared .alert base from yuzu.css, page-specific padding) */
.alert{padding:.5rem 1rem;font-size:.8rem;margin-bottom:.8rem}
.legacy-badge{font-size:.65rem;background:var(--mds-color-theme-outline-secondary);color:var(--mds-color-text-on-accent);padding:.05rem .4rem;border-radius:3px}
</style>
</head><body>

<nav class="nav-bar">
  <a href="/" class="nav-brand">
    <svg class="icon"><use href="/static/icons.svg#home"></use></svg> Yuzu
  </a>
  <a href="/" class="nav-link">Dashboard</a>
  <a href="/instructions" class="nav-link active">Instructions</a>
  <a href="/compliance" class="nav-link">Compliance</a>
  <a href="/tar" class="nav-link">TAR</a>
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

<div style="padding:2rem">
<h1>Instructions</h1>
<div class="tabs">
    <div class="tab active" onclick="showTab('definitions',this)">Definitions</div>
    <div class="tab" onclick="showTab('executions',this)">Executions</div>
    <div class="tab" onclick="showTab('schedules',this)">Schedules</div>
    <div class="tab" onclick="showTab('approvals',this)">Approvals</div>
</div>

<div id="tab-definitions" hx-get="/fragments/instructions" hx-trigger="load" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>
<div id="tab-executions" style="display:none">
    <!-- Execute form — pick instruction, set params, choose scope, dispatch -->
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.2rem;margin-bottom:1.5rem">
      <h3 style="margin:0 0 .8rem 0;font-size:.9rem;border:none;padding:0">Execute Instruction</h3>
      <div style="display:grid;grid-template-columns:1fr 260px;gap:1.2rem">
        <div>
          <div class="form-group" style="margin-bottom:.8rem">
            <label>Instruction Definition</label>
            <select id="exec-def-select" style="width:100%"
                    onchange="onDefSelected(this.value)">
              <option value="">— Select an instruction —</option>
            </select>
          </div>
          <div id="exec-def-info" style="display:none;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:.8rem;margin-bottom:.8rem">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.3rem">
              <strong id="exec-def-name" style="font-size:.85rem"></strong>
              <code id="exec-def-id" style="font-size:.6rem;color:var(--muted)"></code>
            </div>
            <div id="exec-def-desc" style="font-size:.75rem;color:var(--muted);margin-bottom:.3rem"></div>
            <div style="display:flex;gap:1rem;font-size:.7rem">
              <span>Plugin: <code id="exec-def-plugin"></code></span>
              <span>Action: <code id="exec-def-action"></code></span>
              <span>Type: <code id="exec-def-type"></code></span>
            </div>
          </div>
          <div id="exec-params-area" style="display:none;margin-bottom:.8rem">
            <label>Parameters</label>
            <div id="exec-params-fields" class="form-grid" style="margin-top:.3rem"></div>
          </div>
          <div>
            <button class="btn btn-primary" onclick="executeInstruction()" id="exec-btn" disabled>
              Execute
            </button>
            <span id="exec-status" style="font-size:.75rem;color:var(--muted);margin-left:.8rem"></span>
          </div>
          <div id="exec-result" style="margin-top:.5rem"></div>
        </div>
        <div>
          <label>Scope</label>
          <select id="exec-scope" style="width:100%;margin-top:.3rem;margin-bottom:.5rem">
            <option value="__all__">All agents</option>
          </select>
          <div id="exec-agent-list" style="max-height:300px;overflow-y:auto;border:1px solid var(--border);border-radius:4px;font-size:.7rem">
          </div>
        </div>
      </div>
    </div>
    <!-- Execution history — loaded via HTMX fragment -->
    <h3 style="font-size:.9rem;margin-bottom:.5rem;border:none;padding:0">Execution History</h3>
    <div id="exec-history" hx-get="/fragments/executions" hx-trigger="revealed" hx-swap="innerHTML">
      <div class="empty-state">Loading...</div>
    </div>
</div>
<div id="tab-schedules" style="display:none" hx-get="/fragments/schedules" hx-trigger="revealed" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>
<div id="tab-approvals" style="display:none" hx-get="/fragments/approvals" hx-trigger="revealed" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>

<!-- YAML Authoring Panel — rendered by /fragments/instructions/editor -->
<div id="editor-host"></div>

</div><!-- /padding wrapper -->

<div id="toast-container" class="toast-container"></div>
)HTM"
    // Part 2: JavaScript (split to stay under MSVC's 16380-byte string limit)
    R"HTM(
<script>
/* ── Toast notification system ─────────────────────────── */
function showToast(message, level) {
  var c = document.getElementById('toast-container');
  if (!c) return;
  var t = document.createElement('div');
  t.className = 'toast toast-' + (level || 'info');
  t.textContent = message;
  var close = document.createElement('button');
  close.textContent = '\u00d7';
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

function showTab(name, el) {
    document.querySelectorAll('[id^="tab-"]').forEach(d => d.style.display = 'none');
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('tab-' + name).style.display = 'block';
    el.classList.add('active');
}
function openEditor(defId) {
    var url = defId ? '/fragments/instructions/editor?id=' + defId : '/fragments/instructions/editor';
    htmx.ajax('GET', url, {target:'#editor-host', swap:'innerHTML'}).then(function(){
        setTimeout(function() {
            initScrollSync();
            /* Trigger initial preview render for existing YAML */
            var ta = document.getElementById('yaml-editor');
            if (ta && ta.value.trim()) {
                htmx.trigger(ta, 'keyup');
            }
        }, 50);
    });
}
function closeEditor() {
    document.getElementById('editor-host').innerHTML = '';
}
function switchEditorMode(mode, el) {
    document.querySelectorAll('.editor-tab').forEach(t => t.classList.remove('active'));
    el.classList.add('active');
    document.getElementById('form-mode').style.display = mode === 'form' ? 'block' : 'none';
    document.getElementById('yaml-mode').style.display = mode === 'yaml' ? 'block' : 'none';
}
/* Scroll sync between textarea and preview panel */
function initScrollSync() {
    var ta = document.getElementById('yaml-editor');
    var preview = document.getElementById('yaml-preview');
    if (ta && preview) {
        ta.addEventListener('scroll', function() {
            preview.scrollTop = ta.scrollTop;
        });
    }
}

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
loadExecDefinitions();
loadExecAgents();

/* ── Execute tab ──────────────────────────────────────────── */
var execDefs = [];
var selectedDef = null;

function loadExecDefinitions() {
  fetch('/api/instructions?enabled_only=1&limit=500')
    .then(function(r){return r.json()})
    .then(function(data) {
      execDefs = data.definitions || [];
      var sel = document.getElementById('exec-def-select');
      if (!sel) return;
      sel.innerHTML = '<option value="">— Select an instruction —</option>';
      var byPlugin = {};
      execDefs.forEach(function(d) {
        var p = d.plugin || 'other';
        if (!byPlugin[p]) byPlugin[p] = [];
        byPlugin[p].push(d);
      });
      Object.keys(byPlugin).sort().forEach(function(p) {
        var og = document.createElement('optgroup');
        og.label = p;
        byPlugin[p].forEach(function(d) {
          var o = document.createElement('option');
          o.value = d.id;
          o.textContent = d.name || (d.plugin + ' ' + d.action);
          og.appendChild(o);
        });
        sel.appendChild(og);
      });
    });
}

function onDefSelected(defId) {
  selectedDef = null;
  var info = document.getElementById('exec-def-info');
  var paramsArea = document.getElementById('exec-params-area');
  var btn = document.getElementById('exec-btn');

  if (!defId) {
    info.style.display = 'none';
    paramsArea.style.display = 'none';
    btn.disabled = true;
    return;
  }

  selectedDef = execDefs.find(function(d){return d.id === defId});
  if (!selectedDef) return;

  document.getElementById('exec-def-name').textContent = selectedDef.name || '';
  document.getElementById('exec-def-id').textContent = selectedDef.id;
  document.getElementById('exec-def-desc').textContent = selectedDef.description || '';
  document.getElementById('exec-def-plugin').textContent = selectedDef.plugin || '';
  document.getElementById('exec-def-action').textContent = selectedDef.action || '';
  document.getElementById('exec-def-type').textContent = selectedDef.type || '';
  info.style.display = 'block';
  btn.disabled = false;

  var fields = document.getElementById('exec-params-fields');
  fields.innerHTML = '';
  try {
    var schema = typeof selectedDef.parameter_schema === 'string'
      ? JSON.parse(selectedDef.parameter_schema || '{}')
      : (selectedDef.parameter_schema || {});
    var props = schema.properties || {};
    var required = schema.required || [];
    var keys = Object.keys(props);
    if (keys.length > 0) {
      paramsArea.style.display = 'block';
      keys.forEach(function(k) {
        var p = props[k];
        var div = document.createElement('div');
        div.className = 'form-group';
        var lbl = document.createElement('label');
        lbl.textContent = k + (required.indexOf(k) >= 0 ? ' *' : '');
        var inp = document.createElement('input');
        inp.name = 'param_' + k;
        inp.placeholder = p.description || p.type || '';
        if (p.default !== undefined) inp.value = p.default;
        div.appendChild(lbl);
        div.appendChild(inp);
        fields.appendChild(div);
      });
    } else {
      paramsArea.style.display = 'none';
    }
  } catch(e) {
    paramsArea.style.display = 'none';
  }
}
)HTM"
    // Part 3: Execute + form-to-YAML JavaScript
    R"HTM(
function executeInstruction() {
  if (!selectedDef) return;
  var btn = document.getElementById('exec-btn');
  var status = document.getElementById('exec-status');
  btn.disabled = true;
  status.textContent = 'Dispatching...';

  var params = {};
  var fields = document.querySelectorAll('#exec-params-fields input');
  fields.forEach(function(inp) {
    var key = inp.name.replace('param_', '');
    if (inp.value.trim()) params[key] = inp.value.trim();
  });

  var scope = document.getElementById('exec-scope').value;

  var body = {params: params};
  if (scope === '__all__') {
    body.scope = '';
  } else if (scope.startsWith('group:')) {
    body.scope = scope;
  } else {
    body.agent_ids = [scope];
  }

  fetch('/api/instructions/' + encodeURIComponent(selectedDef.id) + '/execute', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  })
  .then(function(r){return r.json().then(function(d){return {status:r.status,data:d}})})
  .then(function(resp) {
    btn.disabled = false;
    if (resp.status >= 400) {
      status.textContent = '';
      var msg = resp.data.error ? (resp.data.error.message || String(resp.data.error)) : 'Failed';
      var errDiv = document.createElement('div');
      errDiv.className = 'alert alert-error';
      errDiv.textContent = msg;
      var er = document.getElementById('exec-result');
      er.innerHTML = '';
      er.appendChild(errDiv);
    } else {
      status.textContent = 'Dispatched to ' + (resp.data.agents_reached || 0) + ' agent(s)';
      var okDiv = document.createElement('div');
      okDiv.className = 'alert alert-success';
      var cmdCode = document.createElement('code');
      cmdCode.textContent = resp.data.command_id || '';
      okDiv.appendChild(document.createTextNode('Command '));
      okDiv.appendChild(cmdCode);
      okDiv.appendChild(document.createTextNode(' dispatched to ' + (resp.data.agents_reached || 0) + ' agent(s)'));
      var er2 = document.getElementById('exec-result');
      er2.innerHTML = '';
      er2.appendChild(okDiv);
    }
  })
  .catch(function(e) {
    btn.disabled = false;
    status.textContent = 'Error: ' + e.message;
  });
}

function loadExecAgents() {
  fetch('/api/agents')
    .then(function(r){return r.json()})
    .then(function(data) {
      var sel = document.getElementById('exec-scope');
      var list = document.getElementById('exec-agent-list');
      if (!sel || !list) return;
      sel.innerHTML = '<option value="__all__">All agents</option>';
      var agents = data.agents || [];
      agents.forEach(function(a) {
        var o = document.createElement('option');
        o.value = a.agent_id || a.id;
        o.textContent = (a.hostname || a.agent_id || a.id) + ' (' + (a.os || '?') + ')';
        sel.appendChild(o);
      });
      list.innerHTML = '';
      agents.forEach(function(a) {
        var row = document.createElement('div');
        row.style.cssText = 'padding:.3rem .5rem;border-bottom:1px solid var(--border)';
        var hn = document.createElement('strong');
        hn.textContent = a.hostname || '?';
        var info = document.createElement('span');
        info.style.color = 'var(--muted)';
        info.textContent = ' ' + (a.os || '') + ' ' + (a.arch || '');
        row.appendChild(hn);
        row.appendChild(info);
        list.appendChild(row);
      });
    })
    .catch(function(){});
}

function formToYaml() {
    var f = document.getElementById('def-form');
    var d = new FormData(f);
    var yaml = 'apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n';
    yaml += '  name: "' + (d.get('name')||'') + '"\n';
    yaml += '  version: "' + (d.get('version')||'1.0.0') + '"\n';
    yaml += 'spec:\n';
    yaml += '  plugin: "' + (d.get('plugin')||'') + '"\n';
    yaml += '  action: "' + (d.get('action')||'') + '"\n';
    yaml += '  type: ' + (d.get('type')||'question') + '\n';
    yaml += '  description: "' + (d.get('description')||'') + '"\n';
    yaml += '  concurrency: ' + (d.get('concurrency_mode')||'unlimited') + '\n';
    yaml += '  approval: ' + (d.get('approval_mode')||'auto') + '\n';
    if (d.get('platforms')) yaml += '  platforms: [' + d.get('platforms') + ']\n';
    yaml += '  parameters:\n    type: object\n    additionalProperties:\n      type: string\n';
    yaml += '  results:\n    - name: output\n      type: string\n';
    var ta = document.getElementById('yaml-editor');
    if (ta) {
        ta.value = yaml;
        htmx.trigger(ta, 'keyup');
    }
    switchEditorMode('yaml', document.querySelectorAll('.editor-tab')[1]);
}
/* Ctrl+K / Cmd+K — navigate to dashboard command palette */
document.addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    window.location.href = '/?palette=1';
  }
});
</script>
</body></html>
)HTM";

// ── Editor fragment HTML template ─────────────────────────────────────────
// Rendered by the server with user role check. Only shown to
// PlatformEngineer and Administrator roles.
extern const char* const kInstructionEditorHtml = R"HTM(
<div class="editor-panel active">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.8rem">
        <div>
            <strong>{{TITLE}}</strong>
            <span class="role-badge">Platform Engineer</span>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="closeEditor()">Close</button>
    </div>
    <div id="editor-alerts"></div>
    <div class="editor-tabs">
        <div class="editor-tab active" onclick="switchEditorMode('form',this)">Form</div>
        <div class="editor-tab" onclick="switchEditorMode('yaml',this)">YAML</div>
    </div>

    <!-- Form mode -->
    <div id="form-mode">
        <form id="def-form">
            <input type="hidden" name="id" value="{{DEF_ID}}">
            <div class="form-grid">
                <div class="form-group">
                    <label>Name</label>
                    <input name="name" value="{{DEF_NAME}}" required placeholder="e.g. hardware:query">
                </div>
                <div class="form-group">
                    <label>Version</label>
                    <input name="version" value="{{DEF_VERSION}}" placeholder="1.0.0">
                </div>
                <div class="form-group">
                    <label>Plugin</label>
                    <input name="plugin" value="{{DEF_PLUGIN}}" required placeholder="e.g. hardware">
                </div>
                <div class="form-group">
                    <label>Action</label>
                    <input name="action" value="{{DEF_ACTION}}" required placeholder="e.g. query">
                </div>
                <div class="form-group">
                    <label>Type</label>
                    <select name="type">
                        <option value="question" {{SEL_QUESTION}}>Question (read-only)</option>
                        <option value="action" {{SEL_ACTION}}>Action (modifying)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Approval Mode</label>
                    <select name="approval_mode">
                        <option value="auto" {{SEL_APPR_AUTO}}>Auto</option>
                        <option value="role-gated" {{SEL_APPR_ROLE}}>Role-gated</option>
                        <option value="always" {{SEL_APPR_ALWAYS}}>Always required</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Concurrency Mode</label>
                    <select name="concurrency_mode">
                        <option value="unlimited" {{SEL_CC_UNLIM}}>Unlimited</option>
                        <option value="per-device" {{SEL_CC_DEV}}>Per-device</option>
                        <option value="per-definition" {{SEL_CC_DEF}}>Per-definition</option>
                        <option value="per-set" {{SEL_CC_SET}}>Per-set</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Platforms</label>
                    <input name="platforms" value="{{DEF_PLATFORMS}}" placeholder="windows, linux, macos">
                </div>
                <div class="form-group full">
                    <label>Description</label>
                    <input name="description" value="{{DEF_DESCRIPTION}}" placeholder="What this instruction does">
                </div>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-secondary" onclick="formToYaml()">Convert to YAML</button>
            </div>
        </form>
    </div>

    <!-- YAML mode -->
    <div id="yaml-mode" style="display:none">
        <form hx-post="/api/instructions/yaml" hx-target="#editor-alerts" hx-swap="innerHTML">
            <input type="hidden" name="id" value="{{DEF_ID}}">
            <div class="form-group full">
                <label>YAML Source (apiVersion: yuzu.io/v1alpha1)</label>
                <div class="yaml-legend">
                    <span><span class="swatch" style="background: var(--mds-color-indicator-success-bright)"></span> question (read-only)</span>
                    <span><span class="swatch" style="background: var(--mds-color-indicator-attention)"></span> action (privileged)</span>
                    <span><span class="swatch" style="background: var(--mds-color-indicator-error-bright)"></span> approval required</span>
                    <span><span class="swatch" style="background: var(--mds-color-theme-indicator-warning)"></span> concurrency</span>
                    <span><span class="swatch" style="background: var(--mds-color-indicator-info-bright)"></span> keys</span>
                    <span><span class="swatch" style="background: var(--mds-color-indicator-special)"></span> schema</span>
                </div>
                <div class="yaml-split">
                    <textarea id="yaml-editor" name="yaml_source"
                              hx-post="/fragments/instructions/yaml-preview"
                              hx-trigger="input changed delay:500ms"
                              hx-target="#yaml-preview"
                              hx-swap="innerHTML"
                              spellcheck="false"
                              placeholder="Paste or type YAML here...">{{YAML_SOURCE}}</textarea>
                    <div id="yaml-preview" class="yaml-preview">
                        <span style="color:var(--muted)">Preview will appear as you type...</span>
                    </div>
                </div>
                <div id="yaml-errors" class="yaml-errors"></div>
            </div>
            <div class="form-actions">
                <button type="submit" class="btn btn-primary">Save Definition</button>
                <button type="button" class="btn btn-secondary"
                        hx-post="/api/instructions/validate-yaml"
                        hx-include="#yaml-editor"
                        hx-target="#editor-alerts" hx-swap="innerHTML">Validate</button>
                <button type="button" class="btn btn-secondary" onclick="closeEditor()">Cancel</button>
            </div>
        </form>
    </div>
</div>
)HTM";

// ── Access denied fragment ────────────────────────────────────────────────
extern const char* const kInstructionEditorDeniedHtml = R"HTM(
<div class="alert alert-error">
    YAML authoring requires the <strong>PlatformEngineer</strong> or <strong>Administrator</strong> role.
    Contact your administrator to request access.
</div>
)HTM";
// NOLINTEND(cert-err58-cpp)
