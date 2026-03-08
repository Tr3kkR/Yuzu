// Settings page HTML — compiled in its own translation unit.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kSettingsHtml =
R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Settings</title>
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
    .file-upload input[type="file"] { display: none; }
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
        <div class="form-row">
          <label>gRPC mTLS</label>
          <label class="toggle">
            <input type="checkbox" id="tls-toggle" onchange="toggleTls()">
            <span class="slider"></span>
          </label>
          <span id="tls-status" style="font-size:0.75rem;color:#8b949e;margin-left:0.5rem"></span>
        </div>

        <div id="tls-fields" style="margin-top:1rem">
          <div class="form-row">
            <label>Server Certificate</label>
            <div class="file-upload">
              <button class="btn btn-secondary" onclick="document.getElementById('cert-file').click()">
                Upload PEM
              </button>
              <input type="file" id="cert-file" accept=".pem,.crt,.cer" onchange="uploadCert('cert')">
              <span class="file-name" id="cert-name">No file</span>
            </div>
          </div>
          <div class="form-row">
            <label>Server Private Key</label>
            <div class="file-upload">
              <button class="btn btn-secondary" onclick="document.getElementById('key-file').click()">
                Upload PEM
              </button>
              <input type="file" id="key-file" accept=".pem,.key" onchange="uploadCert('key')">
              <span class="file-name" id="key-name">No file</span>
            </div>
          </div>
          <div class="form-row">
            <label>CA Certificate</label>
            <div class="file-upload">
              <button class="btn btn-secondary" onclick="document.getElementById('ca-file').click()">
                Upload PEM
              </button>
              <input type="file" id="ca-file" accept=".pem,.crt,.cer" onchange="uploadCert('ca')">
              <span class="file-name" id="ca-name">No file</span>
            </div>
          </div>
        </div>

        <div class="feedback" id="tls-feedback"></div>
      </div>
    </div>

    <!-- ── User Management ───────────────────────────────── -->
    <div class="section">
      <div class="section-header">User Management</div>
      <div class="section-body">
        <table class="user-table">
          <thead>
            <tr><th>Username</th><th>Role</th><th></th></tr>
          </thead>
          <tbody id="user-tbody">
            <tr><td colspan="3" style="color:#484f58">Loading...</td></tr>
          </tbody>
        </table>

        <div class="add-user-form">
          <div class="mini-field">
            <label>Username</label>
            <input type="text" id="new-username" placeholder="username">
          </div>
          <div class="mini-field">
            <label>Password</label>
            <input type="password" id="new-password" placeholder="password">
          </div>
          <div class="mini-field">
            <label>Role</label>
            <select id="new-role">
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <button class="btn btn-primary" onclick="addUser()">Add User</button>
        </div>
        <div class="feedback" id="user-feedback"></div>
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

        <table class="user-table">
          <thead>
            <tr><th>ID</th><th>Label</th><th>Uses</th><th>Expires</th><th>Status</th><th></th></tr>
          </thead>
          <tbody id="token-tbody">
            <tr><td colspan="6" style="color:#484f58">Loading...</td></tr>
          </tbody>
        </table>

        <div class="add-user-form">
          <div class="mini-field">
            <label>Label</label>
            <input type="text" id="token-label" placeholder="e.g. NYC rollout" style="width:160px">
          </div>
          <div class="mini-field">
            <label>Max Uses</label>
            <input type="text" id="token-max-uses" placeholder="0 = unlimited" style="width:80px">
          </div>
          <div class="mini-field">
            <label>TTL (hours)</label>
            <input type="text" id="token-ttl" placeholder="0 = never" style="width:80px">
          </div>
          <button class="btn btn-primary" onclick="createToken()">Generate Token</button>
        </div>
        <div class="feedback" id="token-feedback"></div>

        <!-- One-time token display -->
        <div id="token-reveal" style="display:none;margin-top:1rem;padding:0.75rem;background:#0d1117;border:1px solid var(--green);border-radius:0.3rem">
          <div style="font-size:0.7rem;color:var(--green);margin-bottom:0.3rem;font-weight:600">
            COPY THIS TOKEN NOW — it will not be shown again
          </div>
          <code id="token-raw" style="font-size:0.85rem;word-break:break-all;color:var(--fg);user-select:all"></code>
          <button class="btn btn-secondary" style="margin-top:0.5rem;font-size:0.7rem"
                  onclick="navigator.clipboard.writeText(document.getElementById('token-raw').textContent);this.textContent='Copied!'">
            Copy to Clipboard
          </button>
        </div>
      </div>
    </div>

    <!-- ── Pending Agents ─────────────────────────────────── -->
    <div class="section">
      <div class="section-header">Pending Agent Approvals</div>
      <div class="section-body">
        <p style="font-size:0.75rem;color:#8b949e;margin-bottom:0.75rem">
          Agents that registered without an enrollment token are shown here.
          Approve or deny them to control fleet membership.
        </p>
        <table class="user-table">
          <thead>
            <tr><th>Agent ID</th><th>Hostname</th><th>OS</th><th>Version</th><th>Status</th><th></th></tr>
          </thead>
          <tbody id="pending-tbody">
            <tr><td colspan="6" style="color:#484f58">Loading...</td></tr>
          </tbody>
        </table>
        <div class="feedback" id="pending-feedback"></div>
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
)HTM"
R"HTM(
  <script>
    /* ── TLS state ─────────────────────────────────────────── */
    function loadTlsState() {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', '/api/settings/tls');
      xhr.onload = function() {
        if (xhr.status !== 200) return;
        var data = JSON.parse(xhr.responseText);
        document.getElementById('tls-toggle').checked = data.tls_enabled;
        updateTlsStatus(data.tls_enabled);
        if (data.cert_path) document.getElementById('cert-name').textContent = data.cert_path;
        if (data.key_path)  document.getElementById('key-name').textContent = data.key_path;
        if (data.ca_path)   document.getElementById('ca-name').textContent = data.ca_path;
      };
      xhr.send();
    }

    function updateTlsStatus(on) {
      var el = document.getElementById('tls-status');
      el.textContent = on ? 'Enabled' : 'Disabled';
      el.style.color = on ? '#3fb950' : '#f85149';
      document.getElementById('tls-fields').style.opacity = on ? '1' : '0.4';
    }

    function toggleTls() {
      var enabled = document.getElementById('tls-toggle').checked;
      updateTlsStatus(enabled);
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/settings/tls');
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.onload = function() {
        var fb = document.getElementById('tls-feedback');
        if (xhr.status === 200) {
          fb.className = 'feedback feedback-ok';
          fb.textContent = 'TLS setting updated. Restart required to take effect.';
        } else {
          fb.className = 'feedback feedback-error';
          fb.textContent = 'Failed to update TLS setting.';
        }
      };
      xhr.send(JSON.stringify({ tls_enabled: enabled }));
    }

    /* ── Certificate upload ────────────────────────────────── */
    function uploadCert(type) {
      var inputId = type + '-file';
      var nameId  = type + '-name';
      var file = document.getElementById(inputId).files[0];
      if (!file) return;

      var reader = new FileReader();
      reader.onload = function() {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/settings/cert-upload');
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.onload = function() {
          var fb = document.getElementById('tls-feedback');
          if (xhr.status === 200) {
            var resp = JSON.parse(xhr.responseText);
            document.getElementById(nameId).textContent = resp.path || file.name;
            fb.className = 'feedback feedback-ok';
            fb.textContent = 'Certificate uploaded to ' + (resp.path || '(server)');
          } else {
            fb.className = 'feedback feedback-error';
            try {
              fb.textContent = JSON.parse(xhr.responseText).error;
            } catch(e) {
              fb.textContent = 'Upload failed.';
            }
          }
        };
        xhr.send(JSON.stringify({
          type: type,
          filename: file.name,
          content: reader.result.split(',')[1]  /* base64 data */
        }));
      };
      reader.readAsDataURL(file);
    }

    /* ── User management ───────────────────────────────────── */
    function loadUsers() {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', '/api/settings/users');
      xhr.onload = function() {
        if (xhr.status !== 200) return;
        var users = JSON.parse(xhr.responseText);
        var tbody = document.getElementById('user-tbody');
        if (users.length === 0) {
          tbody.innerHTML = '<tr><td colspan="3" style="color:#484f58">No users</td></tr>';
          return;
        }
        var html = '';
        for (var i = 0; i < users.length; i++) {
          var u = users[i];
          var cls = u.role === 'admin' ? 'role-admin' : 'role-user';
          html += '<tr><td>' + escapeHtml(u.username) + '</td>' +
                  '<td><span class="role-badge ' + cls + '">' + escapeHtml(u.role) + '</span></td>' +
                  '<td><button class="btn btn-danger" style="padding:0.2rem 0.6rem;font-size:0.7rem" ' +
                  'onclick="removeUser(\'' + escapeHtml(u.username) + '\')">Remove</button></td></tr>';
        }
        tbody.innerHTML = html;
      };
      xhr.send();
    }

    function addUser() {
      var username = document.getElementById('new-username').value.trim();
      var password = document.getElementById('new-password').value;
      var role     = document.getElementById('new-role').value;
      var fb = document.getElementById('user-feedback');

      if (!username || !password) {
        fb.className = 'feedback feedback-error';
        fb.textContent = 'Username and password are required.';
        return;
      }

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/settings/users');
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.onload = function() {
        if (xhr.status === 200) {
          fb.className = 'feedback feedback-ok';
          fb.textContent = 'User "' + username + '" added.';
          document.getElementById('new-username').value = '';
          document.getElementById('new-password').value = '';
          loadUsers();
        } else {
          fb.className = 'feedback feedback-error';
          try {
            fb.textContent = JSON.parse(xhr.responseText).error;
          } catch(e) {
            fb.textContent = 'Failed to add user.';
          }
        }
      };
      xhr.send(JSON.stringify({ username: username, password: password, role: role }));
    }

    function removeUser(username) {
      if (!confirm('Remove user "' + username + '"?')) return;
      var xhr = new XMLHttpRequest();
      xhr.open('DELETE', '/api/settings/users/' + encodeURIComponent(username));
      xhr.onload = function() {
        var fb = document.getElementById('user-feedback');
        if (xhr.status === 200) {
          fb.className = 'feedback feedback-ok';
          fb.textContent = 'User "' + username + '" removed.';
          loadUsers();
        } else {
          fb.className = 'feedback feedback-error';
          fb.textContent = 'Failed to remove user.';
        }
      };
      xhr.send();
    }

    function escapeHtml(s) {
      var d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }

    /* ── Enrollment tokens ────────────────────────────────── */
    function loadTokens() {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', '/api/settings/enrollment-tokens');
      xhr.onload = function() {
        if (xhr.status !== 200) return;
        var tokens = JSON.parse(xhr.responseText);
        var tbody = document.getElementById('token-tbody');
        if (tokens.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="color:#484f58">No tokens created</td></tr>';
          return;
        }
        var html = '';
        for (var i = 0; i < tokens.length; i++) {
          var t = tokens[i];
          var uses = t.max_uses === 0 ? t.use_count + ' / \u221e' : t.use_count + ' / ' + t.max_uses;
          var exp = t.expires_at === 0 ? 'Never' : new Date(t.expires_at * 1000).toLocaleString();
          var statusCls = t.revoked ? 'role-user' : 'role-admin';
          var statusTxt = t.revoked ? 'Revoked' : 'Active';
          if (!t.revoked && t.max_uses > 0 && t.use_count >= t.max_uses) {
            statusCls = 'role-user'; statusTxt = 'Exhausted';
          }
          html += '<tr><td><code>' + escapeHtml(t.token_id) + '</code></td>' +
                  '<td>' + escapeHtml(t.label) + '</td>' +
                  '<td>' + uses + '</td>' +
                  '<td style="font-size:0.75rem">' + exp + '</td>' +
                  '<td><span class="role-badge ' + statusCls + '">' + statusTxt + '</span></td>' +
                  '<td>' + (t.revoked ? '' :
                  '<button class="btn btn-danger" style="padding:0.2rem 0.6rem;font-size:0.7rem" ' +
                  'onclick="revokeToken(\'' + escapeHtml(t.token_id) + '\')">Revoke</button>') + '</td></tr>';
        }
        tbody.innerHTML = html;
      };
      xhr.send();
    }

    function createToken() {
      var label = document.getElementById('token-label').value.trim();
      var maxUses = document.getElementById('token-max-uses').value.trim() || '0';
      var ttl = document.getElementById('token-ttl').value.trim() || '0';
      var fb = document.getElementById('token-feedback');

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/settings/enrollment-tokens');
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.onload = function() {
        if (xhr.status === 200) {
          var resp = JSON.parse(xhr.responseText);
          document.getElementById('token-raw').textContent = resp.token;
          document.getElementById('token-reveal').style.display = 'block';
          fb.className = 'feedback feedback-ok';
          fb.textContent = 'Token created. Copy it now!';
          document.getElementById('token-label').value = '';
          document.getElementById('token-max-uses').value = '';
          document.getElementById('token-ttl').value = '';
          loadTokens();
        } else {
          fb.className = 'feedback feedback-error';
          fb.textContent = 'Failed to create token.';
        }
      };
      xhr.send(JSON.stringify({ label: label, max_uses: maxUses, ttl_hours: ttl }));
    }

    function revokeToken(tokenId) {
      if (!confirm('Revoke token "' + tokenId + '"? Agents using this token will no longer be able to enroll.')) return;
      var xhr = new XMLHttpRequest();
      xhr.open('DELETE', '/api/settings/enrollment-tokens/' + encodeURIComponent(tokenId));
      xhr.onload = function() {
        var fb = document.getElementById('token-feedback');
        if (xhr.status === 200) {
          fb.className = 'feedback feedback-ok';
          fb.textContent = 'Token revoked.';
          loadTokens();
        } else {
          fb.className = 'feedback feedback-error';
          fb.textContent = 'Failed to revoke token.';
        }
      };
      xhr.send();
    }

    /* ── Pending agents ───────────────────────────────────── */
    function loadPendingAgents() {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', '/api/settings/pending-agents');
      xhr.onload = function() {
        if (xhr.status !== 200) return;
        var agents = JSON.parse(xhr.responseText);
        var tbody = document.getElementById('pending-tbody');
        if (agents.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="color:#484f58">No pending agents</td></tr>';
          return;
        }
        var html = '';
        for (var i = 0; i < agents.length; i++) {
          var a = agents[i];
          var statusCls = a.status === 'approved' ? 'role-admin' :
                          a.status === 'denied'   ? 'role-user'  : '';
          var statusStyle = a.status === 'pending'
            ? 'background:var(--yellow);color:#000' : '';
          var actions = '';
          if (a.status === 'pending') {
            actions = '<button class="btn btn-primary" style="padding:0.2rem 0.6rem;font-size:0.7rem;margin-right:0.3rem" ' +
                      'onclick="approvePending(\'' + escapeHtml(a.agent_id) + '\')">Approve</button>' +
                      '<button class="btn btn-danger" style="padding:0.2rem 0.6rem;font-size:0.7rem" ' +
                      'onclick="denyPending(\'' + escapeHtml(a.agent_id) + '\')">Deny</button>';
          } else {
            actions = '<button class="btn btn-secondary" style="padding:0.2rem 0.6rem;font-size:0.7rem" ' +
                      'onclick="removePending(\'' + escapeHtml(a.agent_id) + '\')">Remove</button>';
          }
          html += '<tr><td><code style="font-size:0.7rem">' + escapeHtml(a.agent_id).substring(0, 12) + '...</code></td>' +
                  '<td>' + escapeHtml(a.hostname) + '</td>' +
                  '<td>' + escapeHtml(a.os) + ' ' + escapeHtml(a.arch) + '</td>' +
                  '<td>' + escapeHtml(a.agent_version) + '</td>' +
                  '<td><span class="role-badge ' + statusCls + '" style="' + statusStyle + '">' +
                  escapeHtml(a.status) + '</span></td>' +
                  '<td>' + actions + '</td></tr>';
        }
        tbody.innerHTML = html;
      };
      xhr.send();
    }

    function approvePending(agentId) {
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/settings/pending-agents/' + encodeURIComponent(agentId) + '/approve');
      xhr.onload = function() {
        var fb = document.getElementById('pending-feedback');
        if (xhr.status === 200) {
          fb.className = 'feedback feedback-ok';
          fb.textContent = 'Agent approved. It will connect on next retry.';
          loadPendingAgents();
        } else {
          fb.className = 'feedback feedback-error';
          fb.textContent = 'Failed to approve agent.';
        }
      };
      xhr.send();
    }

    function denyPending(agentId) {
      if (!confirm('Deny agent enrollment?')) return;
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/settings/pending-agents/' + encodeURIComponent(agentId) + '/deny');
      xhr.onload = function() {
        var fb = document.getElementById('pending-feedback');
        if (xhr.status === 200) {
          fb.className = 'feedback feedback-ok';
          fb.textContent = 'Agent denied.';
          loadPendingAgents();
        } else {
          fb.className = 'feedback feedback-error';
          fb.textContent = 'Failed to deny agent.';
        }
      };
      xhr.send();
    }

    function removePending(agentId) {
      var xhr = new XMLHttpRequest();
      xhr.open('DELETE', '/api/settings/pending-agents/' + encodeURIComponent(agentId));
      xhr.onload = function() { loadPendingAgents(); };
      xhr.send();
    }

    /* ── Init ──────────────────────────────────────────────── */
    loadTlsState();
    loadUsers();
    loadTokens();
    loadPendingAgents();

    /* Refresh pending agents when SSE notifies us */
    var evtSrc = new EventSource('/events');
    evtSrc.addEventListener('pending-agent', function() { loadPendingAgents(); });
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
