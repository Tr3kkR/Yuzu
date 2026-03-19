// Settings page HTML — compiled in its own translation unit.
// Uses HTMX for all server interactions; no client-side JavaScript except clipboard.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kSettingsHtml =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Settings</title>
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  <script src="https://unpkg.com/htmx-ext-sse@2.2.2/sse.js"></script>
  <style>
    :root {
      --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff;
      --green: #3fb950; --red: #f85149; --yellow: #d29922;
      --surface: #161b22; --border: #30363d;
      --mono: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      background: var(--bg); color: var(--fg);
      min-height: 100vh;
    }

    /* ── Top bar ───────────────────────────────────────────── */
    .topbar {
      display: flex; align-items: center; justify-content: space-between;
      padding: 0.75rem 1.5rem;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }
    .topbar h1 { font-size: 1rem; font-weight: 600; }
    .topbar a {
      color: var(--accent); text-decoration: none; font-size: 0.85rem;
    }
    .topbar a:hover { text-decoration: underline; }

    /* ── Content ───────────────────────────────────────────── */
    .content {
      max-width: 800px; margin: 1.5rem auto; padding: 0 1.5rem;
    }

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

    /* ── Form elements ─────────────────────────────────────── */
    .form-row {
      display: flex; align-items: center; gap: 1rem;
      margin-bottom: 0.75rem;
    }
    .form-row:last-child { margin-bottom: 0; }
    .form-row label {
      flex: 0 0 140px; font-size: 0.8rem; color: #8b949e;
      font-weight: 600;
    }
    .form-row input[type="text"],
    .form-row input[type="password"],
    .form-row select {
      flex: 1; padding: 0.4rem 0.6rem;
      background: var(--bg); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.3rem;
      font-size: 0.8rem; font-family: var(--mono);
      outline: none;
    }
    .form-row input:focus, .form-row select:focus {
      border-color: var(--accent);
    }

    /* ── Toggle switch ─────────────────────────────────────── */
    .toggle {
      position: relative; display: inline-block;
      width: 42px; height: 22px;
    }
    .toggle input { opacity: 0; width: 0; height: 0; }
    .toggle .slider {
      position: absolute; cursor: pointer;
      top: 0; left: 0; right: 0; bottom: 0;
      background: #484f58; border-radius: 22px;
      transition: 0.2s;
    }
    .toggle .slider::before {
      content: ''; position: absolute;
      height: 16px; width: 16px; left: 3px; bottom: 3px;
      background: white; border-radius: 50%;
      transition: 0.2s;
    }
    .toggle input:checked + .slider { background: var(--green); }
    .toggle input:checked + .slider::before { transform: translateX(20px); }

    /* ── Buttons ───────────────────────────────────────────── */
    .btn {
      padding: 0.4rem 1rem; font-size: 0.8rem; font-weight: 500;
      border: none; border-radius: 0.3rem; cursor: pointer;
      transition: opacity 0.15s;
    }
    .btn:hover { opacity: 0.85; }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-danger  { background: var(--red); color: #fff; }
    .btn-secondary {
      background: var(--surface); color: var(--fg);
      border: 1px solid var(--border);
    }
    .btn:disabled { opacity: 0.4; cursor: not-allowed; }

    /* ── File upload ───────────────────────────────────────── */
    .file-upload {
      display: flex; align-items: center; gap: 0.75rem;
    }
    .file-name {
      font-size: 0.75rem; color: #8b949e; font-family: var(--mono);
    }

    /* ── User table ────────────────────────────────────────── */
    .user-table {
      width: 100%; border-collapse: collapse; font-size: 0.8rem;
    }
    .user-table th {
      text-align: left; padding: 0.4rem 0.6rem;
      border-bottom: 2px solid var(--border); color: #8b949e;
      font-size: 0.7rem; text-transform: uppercase;
      letter-spacing: 0.05em; font-weight: 600;
    }
    .user-table td {
      padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border);
    }
    .user-table tr:hover { background: rgba(88,166,255,0.06); }
    .role-badge {
      font-size: 0.7rem; padding: 0.1rem 0.5rem;
      border-radius: 1rem; font-weight: 600;
    }
    .role-admin { background: var(--accent); color: #fff; }
    .role-user  { background: #484f58; color: #fff; }

    /* ── Disabled/coming-soon overlay ──────────────────────── */
    .coming-soon {
      position: relative; opacity: 0.45; pointer-events: none;
    }
    .coming-soon-badge {
      position: absolute; top: 0.75rem; right: 1rem;
      font-size: 0.65rem; padding: 0.15rem 0.5rem;
      background: var(--yellow); color: #000;
      border-radius: 1rem; font-weight: 700;
      pointer-events: auto;
    }

    /* ── Feedback ──────────────────────────────────────────── */
    .feedback {
      font-size: 0.8rem; margin-top: 0.75rem; min-height: 1.2em;
    }
    .feedback-ok    { color: var(--green); }
    .feedback-error { color: var(--red); }

    /* ── Add user form ─────────────────────────────────────── */
    .add-user-form {
      display: flex; gap: 0.5rem; align-items: flex-end;
      margin-top: 1rem; padding-top: 0.75rem;
      border-top: 1px solid var(--border);
    }
    .add-user-form .mini-field {
      display: flex; flex-direction: column; gap: 0.2rem;
    }
    .add-user-form .mini-field label {
      font-size: 0.65rem; color: #8b949e; font-weight: 600;
    }
    .add-user-form input, .add-user-form select {
      padding: 0.35rem 0.5rem;
      background: var(--bg); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.3rem;
      font-size: 0.8rem; outline: none;
    }

    /* ── Token reveal ──────────────────────────────────────── */
    .token-reveal {
      margin-top: 1rem; padding: 0.75rem;
      background: #0d1117; border: 1px solid var(--green);
      border-radius: 0.3rem;
    }
    .token-reveal-header {
      font-size: 0.7rem; color: var(--green);
      margin-bottom: 0.3rem; font-weight: 600;
    }
    .token-reveal code {
      font-size: 0.85rem; word-break: break-all;
      color: var(--fg); user-select: all;
    }

    /* ── HTMX loading indicator ────────────────────────────── */
    .htmx-indicator {
      display: none; color: #8b949e; font-size: 0.75rem;
    }
    .htmx-request .htmx-indicator,
    .htmx-request.htmx-indicator { display: inline; }
  </style>
</head>
<body>

  <div class="topbar">
    <h1>Settings</h1>
    <a href="/">&larr; Back to Dashboard</a>
  </div>

  <div class="content">

    <!-- ── TLS Configuration ─────────────────────────────── -->
    <div class="section">
      <div class="section-header">TLS / mTLS Configuration</div>
      <div class="section-body">
        <!-- TLS fragment loaded via HTMX on page load -->
        <div id="tls-section"
             hx-get="/fragments/settings/tls"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span style="color:#484f58">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── User Management ───────────────────────────────── -->
    <div class="section">
      <div class="section-header">User Management</div>
      <div class="section-body">
        <div id="user-section"
             hx-get="/fragments/settings/users"
             hx-trigger="load, refreshUsers from:body"
             hx-swap="innerHTML">
          <span style="color:#484f58">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Enrollment Tokens ────────────────────────────── -->
    <div class="section">
      <div class="section-header">Enrollment Tokens</div>
      <div class="section-body">
        <p style="font-size:0.75rem;color:#8b949e;margin-bottom:0.75rem">
          Generate pre-shared tokens to auto-enroll agents.
          The raw token is shown <strong>once</strong> — copy it before closing.
        </p>
        <div id="token-section"
             hx-get="/fragments/settings/tokens"
             hx-trigger="load, refreshTokens from:body"
             hx-swap="innerHTML">
          <span style="color:#484f58">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── API Tokens ────────────────────────────────────── -->
    <div class="section">
      <div class="section-header">API Tokens</div>
      <div class="section-body">
        <p style="font-size:0.75rem;color:#8b949e;margin-bottom:0.75rem">
          Generate tokens for programmatic REST API access.
          Pass via <code>Authorization: Bearer &lt;token&gt;</code> or
          <code>X-Yuzu-Token</code> header.
          The raw token is shown <strong>once</strong> — copy it before closing.
        </p>
        <div id="api-token-section"
             hx-get="/fragments/settings/api-tokens"
             hx-trigger="load, refreshApiTokens from:body"
             hx-swap="innerHTML">
          <span style="color:#484f58">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Auto-Approve Policies ─────────────────────────── -->
    <div class="section">
      <div class="section-header">Auto-Approve Policies</div>
      <div class="section-body">
        <p style="font-size:0.75rem;color:#8b949e;margin-bottom:0.75rem">
          Define rules to automatically approve agents on registration.
          Matching agents skip the pending queue entirely.
        </p>
        <div id="auto-approve-section"
             hx-get="/fragments/settings/auto-approve"
             hx-trigger="load, refreshAutoApprove from:body"
             hx-swap="innerHTML">
          <span style="color:#484f58">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Pending Agents ─────────────────────────────────── -->
    <div class="section"
         hx-ext="sse"
         sse-connect="/events">
      <div class="section-header">Pending Agent Approvals</div>
      <div class="section-body">
        <p style="font-size:0.75rem;color:#8b949e;margin-bottom:0.75rem">
          Agents that registered without an enrollment token are shown here.
          Approve or deny them to control fleet membership.
        </p>
        <div id="pending-section"
             hx-get="/fragments/settings/pending"
             hx-trigger="load, sse:pending-agent, refreshPending from:body"
             hx-swap="innerHTML">
          <span style="color:#484f58">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Agent Updates (OTA) ────────────────────────────── -->
    <div class="section">
      <div class="section-header">Agent Updates (OTA)</div>
      <div class="section-body">
        <p style="font-size:0.75rem;color:#8b949e;margin-bottom:0.75rem">
          Upload agent binaries and manage fleet-wide update rollout.
        </p>
        <div id="updates-section"
             hx-get="/fragments/settings/updates"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span style="color:#484f58">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Tag Compliance ──────────────────────────────────── -->
    <div class="section">
      <div class="section-header">Tag Compliance</div>
      <div class="section-body">
        <p style="font-size:0.75rem;color:#8b949e;margin-bottom:0.75rem">
          Devices should have all 4 structured tag categories assigned.
          Devices missing tags are flagged but continue to function normally.
        </p>
        <div id="tag-compliance-section"
             hx-get="/fragments/settings/tag-compliance"
             hx-trigger="load"
             hx-swap="innerHTML">
          <span style="color:#484f58">Loading...</span>
        </div>
      </div>
    </div>

    <!-- ── Directory Integration (coming soon) ───────────── -->
    <div class="section coming-soon">
      <span class="coming-soon-badge">COMING SOON</span>
      <div class="section-header">Directory Integration</div>
      <div class="section-body">
        <div class="form-row">
          <label>Auth Source</label>
          <select disabled>
            <option>Local accounts</option>
            <option>Active Directory</option>
            <option>Microsoft Entra ID</option>
          </select>
        </div>
        <div class="form-row">
          <label>Inherit roles from</label>
          <select disabled>
            <option>Manual assignment</option>
            <option>AD Security Groups</option>
            <option>Entra Roles</option>
          </select>
        </div>
        <p style="font-size:0.75rem;color:#8b949e;margin-top:0.75rem">
          Domain-joined and non-domain-joined machines will both be supported.
          Agents report domain membership via the <code>device_identity</code> plugin.
        </p>
      </div>
    </div>

  </div>

  <script>
    /* Minimal vanilla JS — only for clipboard copy (no HTMX equivalent) */
    document.body.addEventListener('click', function(e) {
      if (e.target.closest('[data-copy-token]')) {
        var btn = e.target.closest('[data-copy-token]');
        var code = btn.parentElement.querySelector('code');
        if (code) {
          navigator.clipboard.writeText(code.textContent);
          btn.textContent = 'Copied!';
          setTimeout(function() { btn.textContent = 'Copy to Clipboard'; }, 2000);
        }
      }
    });
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
