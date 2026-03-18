// Instruction management page with YAML authoring UI.
// HTMX-driven with CodeMirror 6 YAML editor for Platform Engineers.
// The authoring panel (New/Edit) is only shown to users with the
// PlatformEngineer or Administrator role.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kInstructionPageHtml = R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Instructions</title>
<script src="https://unpkg.com/htmx.org@1.9.12"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@codemirror/view@6/dist/index.css">
<style>
body{background:#0d1117;color:#c9d1d9;font-family:system-ui,-apple-system,sans-serif;margin:0;padding:2rem}
a{color:#58a6ff}h1{border-bottom:1px solid #21262d;padding-bottom:.5rem}
.tabs{display:flex;gap:.5rem;margin-bottom:1rem;border-bottom:1px solid #21262d;padding-bottom:.5rem}
.tab{padding:.4rem 1rem;cursor:pointer;border:1px solid transparent;border-radius:6px 6px 0 0;color:#8b949e}
.tab.active,.tab:hover{color:#c9d1d9;border-color:#30363d;background:#161b22}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #21262d;font-size:.8rem}
th{color:#8b949e;font-weight:600}
.empty-state{color:#8b949e;text-align:center;padding:2rem}
.status-badge{display:inline-block;padding:.1rem .5rem;border-radius:1rem;font-size:.7rem;font-weight:600}
.status-pending{background:#d29922;color:#0d1117}
.status-running{background:#1f6feb;color:#fff}
.status-completed{background:#238636;color:#fff}
.status-cancelled{background:#6e7681;color:#fff}
.status-failed{background:#da3633;color:#fff}
.status-approved{background:#238636;color:#fff}
.status-rejected{background:#da3633;color:#fff}
.btn{border:none;border-radius:6px;padding:.3rem .8rem;cursor:pointer;font-size:.75rem;font-weight:600;margin-right:.3rem}
.btn-primary{background:#238636;color:#fff}
.btn-secondary{background:#21262d;color:#c9d1d9;border:1px solid #30363d}
.btn-danger{background:#da3633;color:#fff}
.btn-sm{padding:.2rem .5rem;font-size:.7rem}
.progress-bar{width:80px;height:8px;background:#21262d;border-radius:4px;display:inline-block;vertical-align:middle}
.progress-fill{height:100%;background:#238636;border-radius:4px}
code{background:#161b22;padding:.1rem .3rem;border-radius:4px;font-size:.75rem}
.toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:.8rem}
.role-badge{display:inline-block;padding:.1rem .4rem;border-radius:4px;font-size:.65rem;
  font-weight:600;background:#1f6feb;color:#fff;margin-left:.5rem;vertical-align:middle}
/* Editor panel */
.editor-panel{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.2rem;margin-bottom:1rem;display:none}
.editor-panel.active{display:block}
.editor-tabs{display:flex;gap:.3rem;margin-bottom:1rem}
.editor-tab{padding:.3rem .8rem;cursor:pointer;border:1px solid #30363d;border-radius:4px;
  font-size:.75rem;color:#8b949e;background:transparent}
.editor-tab.active{color:#c9d1d9;background:#21262d}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:.8rem}
.form-group{display:flex;flex-direction:column;gap:.2rem}
.form-group.full{grid-column:1/-1}
label{font-size:.75rem;color:#8b949e;font-weight:600}
input,select,textarea{background:#0d1117;border:1px solid #30363d;border-radius:4px;
  padding:.4rem .6rem;color:#c9d1d9;font-size:.8rem;font-family:inherit}
textarea{font-family:'Cascadia Code','Fira Code',monospace;min-height:300px;resize:vertical;tab-size:2}
input:focus,select:focus,textarea:focus{border-color:#58a6ff;outline:none}
.form-actions{margin-top:1rem;display:flex;gap:.5rem}
.alert{padding:.5rem 1rem;border-radius:6px;font-size:.8rem;margin-bottom:.8rem}
.alert-error{background:#3d1418;border:1px solid #da3633;color:#f85149}
.alert-success{background:#0d2818;border:1px solid #238636;color:#3fb950}
.legacy-badge{font-size:.65rem;background:#6e7681;color:#fff;padding:.05rem .4rem;border-radius:3px}
</style>
</head><body>
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
<div id="tab-executions" style="display:none" hx-get="/fragments/executions" hx-trigger="revealed" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>
<div id="tab-schedules" style="display:none" hx-get="/fragments/schedules" hx-trigger="revealed" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>
<div id="tab-approvals" style="display:none" hx-get="/fragments/approvals" hx-trigger="revealed" hx-swap="innerHTML">
    <div class="empty-state">Loading...</div>
</div>

<!-- YAML Authoring Panel — rendered by /fragments/instructions/editor -->
<div id="editor-host"></div>

<script>
function showTab(name, el) {
    document.querySelectorAll('[id^="tab-"]').forEach(d => d.style.display = 'none');
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('tab-' + name).style.display = 'block';
    el.classList.add('active');
}
function openEditor(defId) {
    var url = defId ? '/fragments/instructions/editor?id=' + defId : '/fragments/instructions/editor';
    htmx.ajax('GET', url, {target:'#editor-host', swap:'innerHTML'});
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
    document.getElementById('yaml-source').value = yaml;
    switchEditorMode('yaml', document.querySelectorAll('.editor-tab')[1]);
}
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
                <textarea id="yaml-source" name="yaml_source" spellcheck="false">{{YAML_SOURCE}}</textarea>
            </div>
            <div class="form-actions">
                <button type="submit" class="btn btn-primary">Save Definition</button>
                <button type="button" class="btn btn-secondary"
                        hx-post="/api/instructions/validate-yaml"
                        hx-include="#yaml-source"
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
