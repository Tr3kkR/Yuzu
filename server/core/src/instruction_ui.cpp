// Instruction management page — Phase 2 stub.
// Full HTMX instruction management page with tabs for definitions,
// executions, schedules, and approvals.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kInstructionPageHtml = R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Instructions</title>
<script src="https://unpkg.com/htmx.org@1.9.12"></script>
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
.btn{border:none;border-radius:6px;padding:.3rem .8rem;cursor:pointer;font-size:.75rem;font-weight:600}
.btn-primary{background:#238636;color:#fff}
.btn-danger{background:#da3633;color:#fff}
.progress-bar{width:80px;height:8px;background:#21262d;border-radius:4px;display:inline-block;vertical-align:middle}
.progress-fill{height:100%;background:#238636;border-radius:4px}
code{background:#161b22;padding:.1rem .3rem;border-radius:4px;font-size:.75rem}
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

<script>
function showTab(name, el) {
    document.querySelectorAll('[id^="tab-"]').forEach(d => d.style.display = 'none');
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('tab-' + name).style.display = 'block';
    el.classList.add('active');
}
</script>
</body></html>
)HTM";
// NOLINTEND(cert-err58-cpp)
