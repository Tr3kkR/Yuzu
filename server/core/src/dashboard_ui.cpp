// Unified dashboard UI HTML — compiled in its own translation unit to isolate
// the long raw string literal from MSVC's brace-matching in server.cpp.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kDashboardIndexHtml =
// Part 1: CSS + HTML markup (split to stay under MSVC's 16380-byte string limit)
R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Dashboard</title>
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
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
      display: grid; height: 100vh;
      grid-template-rows: auto 1fr auto;
      grid-template-columns: 1fr 260px;
      grid-template-areas:
        "instrbar  scope"
        "results   scope"
        "footer    scope";
    }

    /* ── Instruction Bar ─────────────────────────────────────── */
    .instr-bar {
      grid-area: instrbar;
      display: flex; align-items: center; gap: 0.75rem;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }
    .instr-bar label {
      font-size: 0.8rem; font-weight: 600; color: #8b949e;
      white-space: nowrap;
    }
    .instr-bar input[type="text"] {
      flex: 1; padding: 0.45rem 0.75rem;
      background: var(--bg); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.375rem;
      font-size: 0.875rem; font-family: var(--mono);
      outline: none;
    }
    .instr-bar input[type="text"]:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 2px rgba(88,166,255,0.2);
    }
    .instr-bar input[type="text"]::placeholder { color: #484f58; }
    .instr-bar button {
      padding: 0.45rem 1.2rem; font-size: 0.875rem; font-weight: 500;
      background: var(--accent); color: #fff; border: none;
      border-radius: 0.375rem; cursor: pointer; transition: opacity 0.15s;
    }
    .instr-bar button:hover { opacity: 0.85; }
    .instr-bar button:disabled { opacity: 0.4; cursor: not-allowed; }
    #status-badge {
      font-size: 0.7rem; padding: 0.15rem 0.5rem;
      border-radius: 1rem; font-weight: 600;
    }
    .badge-idle     { background: #484f58; color: #fff; }
    .badge-running  { background: var(--green); color: #fff; }
    .badge-done     { background: var(--green); color: #fff; }
    .badge-error    { background: var(--red); color: #fff; }
    .btn-clear {
      padding: 0.45rem 0.8rem; font-size: 0.8rem; font-weight: 500;
      background: var(--surface); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.375rem;
      cursor: pointer; transition: opacity 0.15s;
    }
    .btn-clear:hover { opacity: 0.85; }

    /* ── Stats row ───────────────────────────────────────────── */
    .stats {
      display: flex; gap: 1.2rem; align-items: center;
      font-size: 0.75rem; color: #8b949e; white-space: nowrap;
    }

    /* ── Results Area ────────────────────────────────────────── */
    .results {
      grid-area: results;
      overflow-y: auto;
      display: flex; flex-direction: column;
    }
    .results-header {
      display: flex; align-items: center; gap: 0.75rem;
      padding: 0.5rem 1rem;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }
    .results-header h2 { font-size: 0.85rem; font-weight: 600; }
    .table-wrap {
      flex: 1; overflow-y: auto;
    }
    table {
      width: 100%; border-collapse: collapse; font-size: 0.8rem;
    }
    thead th {
      position: sticky; top: 0; background: var(--surface);
      text-align: left; padding: 0.45rem 0.6rem;
      border-bottom: 2px solid var(--border); font-weight: 600;
      color: #8b949e; text-transform: uppercase; font-size: 0.65rem;
      letter-spacing: 0.05em;
    }
    tbody td {
      padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border);
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      max-width: 300px;
    }
    tbody tr:hover { background: rgba(88,166,255,0.06); }
    .col-agent {
      font-family: var(--mono); font-size: 0.7rem;
      color: var(--yellow); width: 10rem;
    }
    .col-mono {
      font-family: var(--mono); font-size: 0.75rem;
    }
    .empty-state {
      text-align: center; padding: 3rem 1rem; color: #484f58;
      font-size: 0.85rem;
    }

    /* ── Scope Panel ─────────────────────────────────────────── */
    .scope {
      grid-area: scope;
      display: flex; flex-direction: column;
      border-left: 1px solid var(--border);
      background: var(--surface);
    }
    .scope-header {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      font-size: 0.8rem; font-weight: 600;
    }
    .scope-count {
      font-weight: 400; color: #8b949e; font-size: 0.7rem;
      margin-left: 0.5rem;
    }
    .scope-list {
      flex: 1; overflow-y: auto; padding: 0.25rem 0;
    }
    .scope-item {
      display: flex; flex-direction: column; gap: 0.1rem;
      padding: 0.45rem 1rem; cursor: pointer;
      border-left: 3px solid transparent;
      transition: background 0.1s;
    }
    .scope-item:hover { background: rgba(88,166,255,0.06); }
    .scope-item.selected {
      background: rgba(88,166,255,0.1);
      border-left-color: var(--accent);
    }
    .scope-item-name {
      font-size: 0.8rem; font-weight: 500;
    }
    .scope-item-meta {
      font-size: 0.65rem; color: #8b949e;
      font-family: var(--mono);
    }
    .scope-item-all {
      font-weight: 600; color: var(--accent);
    }
    .scope-item .online-dot {
      display: inline-block; width: 6px; height: 6px;
      border-radius: 50%; background: var(--green);
      margin-right: 0.35rem; vertical-align: middle;
    }

    /* ── Footer ──────────────────────────────────────────────── */
    footer {
      grid-area: footer;
      padding: 0.4rem 1rem; border-top: 1px solid var(--border);
      font-size: 0.7rem; color: #484f58;
    }

    /* ── Hamburger Menu ──────────────────────────────────────── */
    .hamburger-wrap {
      position: relative; margin-left: auto;
    }
    .hamburger-btn {
      background: none; border: 1px solid var(--border); border-radius: 0.375rem;
      color: var(--fg); font-size: 1.2rem; padding: 0.2rem 0.55rem;
      cursor: pointer; line-height: 1; transition: background 0.15s;
    }
    .hamburger-btn:hover { background: rgba(88,166,255,0.1); }
    .hamburger-menu {
      display: none; position: absolute; right: 0; top: 110%;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 0.5rem; min-width: 160px; z-index: 1000;
      box-shadow: 0 8px 24px rgba(0,0,0,0.4);
      overflow: hidden;
    }
    .hamburger-menu.open { display: block; }
    .hamburger-menu a, .hamburger-menu button {
      display: block; width: 100%; padding: 0.55rem 1rem;
      font-size: 0.8rem; color: var(--fg); text-align: left;
      text-decoration: none; background: none; border: none;
      cursor: pointer; transition: background 0.1s;
    }
    .hamburger-menu a:hover, .hamburger-menu button:hover {
      background: rgba(88,166,255,0.1);
    }
    .hamburger-menu .divider {
      height: 1px; background: var(--border); margin: 0.25rem 0;
    }
    .hamburger-user {
      padding: 0.55rem 1rem; font-size: 0.7rem; color: #8b949e;
      border-bottom: 1px solid var(--border);
    }

    /* ── About Modal ─────────────────────────────────────────── */
    .modal-overlay {
      display: none; position: fixed; inset: 0;
      background: rgba(0,0,0,0.6); z-index: 2000;
      align-items: center; justify-content: center;
    }
    .modal-overlay.open { display: flex; }
    .modal {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 0.75rem; padding: 2rem; width: 380px;
      text-align: center;
    }
    .modal h2 { font-size: 1.3rem; margin-bottom: 0.5rem; }
    .modal .version { font-size: 0.8rem; color: #8b949e; margin-bottom: 1rem; }
    .modal p { font-size: 0.8rem; color: #8b949e; line-height: 1.5; margin-bottom: 1rem; }
    .modal .btn-close {
      padding: 0.4rem 1.5rem; font-size: 0.8rem; font-weight: 500;
      background: var(--accent); color: #fff; border: none;
      border-radius: 0.375rem; cursor: pointer;
    }
  </style>
</head>
<body>

  <!-- ── Instruction Bar ────────────────────────────────────── -->
  <div class="instr-bar">
    <label>Instruction</label>
    <input type="text" id="instr-input" placeholder="status, os_info, hardware, users, installed_apps, msi_packages, network_config, netstat, sockwho, procfetch"
           autocomplete="off" spellcheck="false">
    <button id="btn-send" onclick="sendInstruction()">Send</button>
    <span id="status-badge" class="badge-idle">IDLE</span>
    <button class="btn-clear" onclick="clearResults()">Clear</button>
    <div class="stats">
      <span>Rows: <strong id="row-count">0</strong></span>
      <span>Network: <strong id="stat-network">&mdash;</strong></span>
      <span>Agent: <strong id="stat-agent">&mdash;</strong></span>
      <span>Total: <strong id="stat-total">&mdash;</strong></span>
    </div>
    <div class="hamburger-wrap">
      <button class="hamburger-btn" onclick="toggleMenu()" title="Menu">&#9776;</button>
      <div class="hamburger-menu" id="hamburger-menu">
        <div class="hamburger-user" id="menu-user">Signed in</div>
        <a href="/settings">Settings</a>
        <button onclick="showAbout()">About</button>
        <div class="divider"></div>
        <button onclick="doLogout()">Logout</button>
      </div>
    </div>
  </div>

  <!-- ── About Modal ──────────────────────────────────────── -->
  <div class="modal-overlay" id="about-modal" onclick="closeAbout(event)">
    <div class="modal">
      <h2>Yuzu</h2>
      <div class="version">Agent &amp; Server Management Platform</div>
      <p>Real-time endpoint management with gRPC/Protobuf transport,
         plugin architecture, and multi-platform support.</p>
      <p style="font-size:0.7rem">Built with C++23, gRPC, httplib, spdlog.</p>
      <button class="btn-close" onclick="closeAbout()">Close</button>
    </div>
  </div>

)HTM"
// Part 2: HTML body continued
R"HTM(
  <!-- ── Results ────────────────────────────────────────────── -->
  <div class="results">
    <div class="results-header">
      <h2>Results</h2>
      <span id="result-context" style="font-size:0.75rem;color:#8b949e"></span>
    </div>
    <div class="table-wrap">
      <table>
        <thead id="results-thead"><tr></tr></thead>
        <tbody id="results-tbody">
          <tr id="empty-row"><td colspan="1" class="empty-state">
            Type an instruction above and press <strong>Send</strong> to execute.
          </td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ── Scope Panel ────────────────────────────────────────── -->
  <div class="scope">
    <div class="scope-header">
      Scope <span class="scope-count" id="agent-count">0 agents</span>
    </div>
    <div class="scope-list" id="scope-list">
      <div class="scope-item selected" data-agent-id="__all__" onclick="selectScope(this)">
        <span class="scope-item-name scope-item-all">All Agents</span>
        <span class="scope-item-meta">Broadcast to every connected agent</span>
      </div>
    </div>
  </div>

  <footer>Yuzu Server &mdash; Dashboard</footer>
)HTM"
// Part 2: JavaScript
R"HTM(
  <script>
    /* ── State ─────────────────────────────────────────────── */
    var selectedScope = '__all__';
    var rowCount = 0;
    var currentInstruction = '';
    var agents = {};   // agent_id -> { hostname, os, arch }
    var evtSource = null;

    /* ── Instruction mapping ──────────────────────────────── */
    var instructionMap = {
      'chargen':          { plugin: 'chargen',   action: 'chargen_start' },
      'chargen stop':     { plugin: 'chargen',   action: 'chargen_stop' },
      'procfetch':        { plugin: 'procfetch', action: 'procfetch_fetch' },
      'netstat':          { plugin: 'netstat',   action: 'netstat_list' },
      'sockwho':          { plugin: 'sockwho',   action: 'sockwho_list' },
      'status':           { plugin: 'status',    action: 'info' },
      'status version':   { plugin: 'status',    action: 'version' },
      'status info':      { plugin: 'status',    action: 'info' },
      'status health':    { plugin: 'status',    action: 'health' },
      'status plugins':   { plugin: 'status',    action: 'plugins' },
      'status connection': { plugin: 'status',   action: 'connection' },
      'status config':    { plugin: 'status',    action: 'config' },
      'device_identity':          { plugin: 'device_identity', action: 'device_name' },
      'device_identity domain':   { plugin: 'device_identity', action: 'domain' },
      'device_identity ou':       { plugin: 'device_identity', action: 'ou' },
      'os_info':                  { plugin: 'os_info', action: 'os_name' },
      'os_info os_name':          { plugin: 'os_info', action: 'os_name' },
      'os_info os_version':       { plugin: 'os_info', action: 'os_version' },
      'os_info os_build':         { plugin: 'os_info', action: 'os_build' },
      'os_info os_arch':          { plugin: 'os_info', action: 'os_arch' },
      'os_info uptime':           { plugin: 'os_info', action: 'uptime' },
      'hardware':                 { plugin: 'hardware', action: 'manufacturer' },
      'hardware manufacturer':    { plugin: 'hardware', action: 'manufacturer' },
      'hardware model':           { plugin: 'hardware', action: 'model' },
      'hardware bios':            { plugin: 'hardware', action: 'bios' },
      'hardware processors':     { plugin: 'hardware', action: 'processors' },
      'hardware memory':          { plugin: 'hardware', action: 'memory' },
      'hardware disks':           { plugin: 'hardware', action: 'disks' },
      'users':                    { plugin: 'users', action: 'logged_on' },
      'users logged_on':          { plugin: 'users', action: 'logged_on' },
      'users sessions':           { plugin: 'users', action: 'sessions' },
      'users local_users':        { plugin: 'users', action: 'local_users' },
      'users local_admins':       { plugin: 'users', action: 'local_admins' },
      'installed_apps':            { plugin: 'installed_apps', action: 'list' },
      'installed_apps list':       { plugin: 'installed_apps', action: 'list' },
      'installed_apps query':      { plugin: 'installed_apps', action: 'query' },
      'msi_packages':              { plugin: 'msi_packages', action: 'list' },
      'msi_packages list':         { plugin: 'msi_packages', action: 'list' },
      'msi_packages product_codes': { plugin: 'msi_packages', action: 'product_codes' },
      'network_config':              { plugin: 'network_config', action: 'adapters' },
      'network_config adapters':     { plugin: 'network_config', action: 'adapters' },
      'network_config ip_addresses': { plugin: 'network_config', action: 'ip_addresses' },
      'network_config dns_servers':  { plugin: 'network_config', action: 'dns_servers' },
      'network_config proxy':        { plugin: 'network_config', action: 'proxy' }
    };

    /* ── Column schemas per plugin ────────────────────────── */
    var columnSchemas = {
      'chargen':   ['Agent', 'Output'],
      'procfetch': ['Agent', 'PID', 'Name', 'Path', 'SHA-1'],
      'netstat':   ['Agent', 'Proto', 'Local Addr', 'Local Port', 'Remote Addr', 'Remote Port', 'State', 'PID'],
      'sockwho':   ['Agent', 'PID', 'Name', 'Path', 'Proto', 'Local Addr', 'Local Port', 'Remote Addr', 'Remote Port', 'State'],
      'status':            ['Agent', 'Key', 'Value'],
      'device_identity':   ['Agent', 'Key', 'Value'],
      'os_info':           ['Agent', 'Key', 'Value'],
      'hardware':          ['Agent', 'Key', 'Value'],
      'users':             ['Agent', 'Key', 'Value'],
      'installed_apps':    ['Agent', 'Key', 'Value'],
      'msi_packages':     ['Agent', 'Key', 'Value'],
      'network_config':   ['Agent', 'Key', 'Value']
    };

    /* ── Helpers ──────────────────────────────────────────── */
    function escapeHtml(s) {
      var d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }

    function setBadge(state) {
      var el = document.getElementById('status-badge');
      var map = {
        idle:    { text: 'IDLE',    cls: 'badge-idle' },
        running: { text: 'RUNNING', cls: 'badge-running' },
        done:    { text: 'DONE',    cls: 'badge-done' },
        error:   { text: 'ERROR',   cls: 'badge-error' }
      };
      var s = map[state] || map.idle;
      el.textContent = s.text;
      el.className = s.cls;
    }

    /* ── Table management ─────────────────────────────────── */
    function setColumns(cols) {
      var thead = document.getElementById('results-thead');
      var html = '<tr>';
      for (var i = 0; i < cols.length; i++) {
        var cls = i === 0 ? ' class="col-agent"' : '';
        html += '<th' + cls + '>' + escapeHtml(cols[i]) + '</th>';
      }
      html += '</tr>';
      thead.innerHTML = html;
    }

    function addRow(cells) {
      var er = document.getElementById('empty-row');
      if (er) er.remove();

      var tbody = document.getElementById('results-tbody');
      var tr = document.createElement('tr');
      var html = '';
      for (var i = 0; i < cells.length; i++) {
        var cls = i === 0 ? ' class="col-agent"' : '';
        html += '<td' + cls + ' title="' + escapeHtml(cells[i]) + '">' + escapeHtml(cells[i]) + '</td>';
      }
      tr.innerHTML = html;
      tbody.appendChild(tr);

      rowCount++;
      document.getElementById('row-count').textContent = rowCount.toLocaleString();

      /* Auto-scroll to bottom */
      var wrap = document.querySelector('.table-wrap');
      wrap.scrollTop = wrap.scrollHeight;
    }

    function clearResults() {
      document.getElementById('results-tbody').innerHTML = '';
      document.getElementById('results-thead').innerHTML = '<tr></tr>';
      rowCount = 0;
      document.getElementById('row-count').textContent = '0';
      document.getElementById('stat-network').innerHTML = '&mdash;';
      document.getElementById('stat-agent').innerHTML = '&mdash;';
      document.getElementById('stat-total').innerHTML = '&mdash;';
      document.getElementById('result-context').textContent = '';
      setBadge('idle');
    }

    /* ── Scope management ─────────────────────────────────── */
    function selectScope(el) {
      var items = document.querySelectorAll('.scope-item');
      for (var i = 0; i < items.length; i++) items[i].classList.remove('selected');
      el.classList.add('selected');
      selectedScope = el.getAttribute('data-agent-id');
    }

    function refreshAgentList() {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', '/api/agents');
      xhr.onload = function() {
        if (xhr.status !== 200) return;
        var list = JSON.parse(xhr.responseText);
        agents = {};
        for (var i = 0; i < list.length; i++) {
          agents[list[i].agent_id] = list[i];
        }
        renderAgentList();
      };
      xhr.send();
    }

    function renderAgentList() {
      var container = document.getElementById('scope-list');
      var prevSelected = selectedScope;

      /* Keep the "All" item, rebuild the rest */
      var html = '<div class="scope-item' + (prevSelected === '__all__' ? ' selected' : '') +
                 '" data-agent-id="__all__" onclick="selectScope(this)">' +
                 '<span class="scope-item-name scope-item-all">All Agents</span>' +
                 '<span class="scope-item-meta">Broadcast to every connected agent</span></div>';

      var ids = Object.keys(agents).sort();
      for (var i = 0; i < ids.length; i++) {
        var a = agents[ids[i]];
        var sel = prevSelected === ids[i] ? ' selected' : '';
        html += '<div class="scope-item' + sel + '" data-agent-id="' + escapeHtml(ids[i]) +
                '" onclick="selectScope(this)">' +
                '<span class="scope-item-name"><span class="online-dot"></span>' +
                escapeHtml(a.hostname || ids[i]) + '</span>' +
                '<span class="scope-item-meta">' +
                escapeHtml(ids[i].substring(0, 12)) + ' · ' +
                escapeHtml(a.os || '?') + '/' + escapeHtml(a.arch || '?') +
                '</span></div>';
      }

      container.innerHTML = html;
      document.getElementById('agent-count').textContent = ids.length + ' agent' + (ids.length !== 1 ? 's' : '');
    }

    function agentDisplayName(agentId) {
      var a = agents[agentId];
      if (a && a.hostname) return a.hostname;
      if (agentId && agentId.length > 12) return agentId.substring(0, 12);
      return agentId || '?';
    }

    /* ── Send instruction ─────────────────────────────────── */
    function sendInstruction() {
      var input = document.getElementById('instr-input');
      var raw = input.value.trim().toLowerCase();
      if (!raw) return;

      var mapped = instructionMap[raw];
      if (!mapped) {
        setBadge('error');
        document.getElementById('result-context').textContent =
          'Unknown instruction: "' + raw + '". Try: status, os_info, hardware, users, installed_apps, msi_packages, network_config, netstat, sockwho, procfetch, chargen';
        return;
      }

      currentInstruction = raw;

      /* Set up columns for this plugin */
      var schema = columnSchemas[mapped.plugin] || ['Agent', 'Output'];
      setColumns(schema);

      /* Determine target agent IDs */
      var agentIds = [];
      if (selectedScope !== '__all__') {
        agentIds.push(selectedScope);
      }

      var payload = JSON.stringify({
        plugin:    mapped.plugin,
        action:    mapped.action,
        agent_ids: agentIds
      });

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/command');
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.onload = function() {
        if (xhr.status === 200) {
          setBadge('running');
          document.getElementById('result-context').textContent = raw + ' → scope: ' +
            (selectedScope === '__all__' ? 'all agents' : agentDisplayName(selectedScope));
        } else {
          setBadge('error');
          try {
            var err = JSON.parse(xhr.responseText);
            document.getElementById('result-context').textContent = err.error || 'Command failed';
          } catch(e) {
            document.getElementById('result-context').textContent = 'Command failed (HTTP ' + xhr.status + ')';
          }
        }
      };
      xhr.send(payload);
    }

    /* Enter key in input sends instruction */
    document.getElementById('instr-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { e.preventDefault(); sendInstruction(); }
    });
)HTM"
// Part 4: SSE + menu JavaScript
R"HTM(
    /* ── SSE ──────────────────────────────────────────────── */
    function connectSSE() {
      if (evtSource) evtSource.close();
      evtSource = new EventSource('/events');

      evtSource.addEventListener('output', function(e) {
        /* Format: agent_id|plugin|data... */
        var sep1 = e.data.indexOf('|');
        if (sep1 < 0) return;
        var sep2 = e.data.indexOf('|', sep1 + 1);
        if (sep2 < 0) return;

        var agentId = e.data.substring(0, sep1);
        var plugin  = e.data.substring(sep1 + 1, sep2);
        var payload = e.data.substring(sep2 + 1);
        var agentName = agentDisplayName(agentId);

        if (plugin === 'chargen') {
          addRow([agentName, payload]);
        } else if (plugin === 'procfetch') {
          /* pid|name|path|sha1 */
          var parts = payload.split('|');
          if (parts.length >= 4) {
            addRow([agentName, parts[0], parts[1].replace(/\\\|/g,'|'),
                    parts[2].replace(/\\\|/g,'|'), parts[3]]);
          } else {
            addRow([agentName, payload]);
          }
        } else if (plugin === 'netstat') {
          /* proto|local_addr|local_port|remote_addr|remote_port|state|pid */
          var parts = payload.split('|');
          if (parts.length >= 7) {
            addRow([agentName, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]]);
          } else {
            addRow([agentName, payload]);
          }
        } else if (plugin === 'sockwho') {
          /* pid|name|path|proto|local_addr|local_port|remote_addr|remote_port|state */
          var parts = payload.split('|');
          if (parts.length >= 9) {
            addRow([agentName, parts[0],
                    parts[1].replace(/\\\|/g,'|'),
                    parts[2].replace(/\\\|/g,'|'),
                    parts[3], parts[4], parts[5], parts[6], parts[7], parts[8]]);
          } else {
            addRow([agentName, payload]);
          }
        } else if (plugin === 'status' || plugin === 'device_identity' || plugin === 'os_info' || plugin === 'hardware' || plugin === 'users' || plugin === 'installed_apps' || plugin === 'msi_packages' || plugin === 'network_config') {
          /* key|value */
          var parts = payload.split('|');
          if (parts.length >= 2) {
            addRow([agentName, parts[0], parts.slice(1).join('|')]);
          } else {
            addRow([agentName, payload, '']);
          }
        } else {
          addRow([agentName, payload]);
        }
      });

      evtSource.addEventListener('command-status', function(e) {
        /* Format: command_id|status */
        var parts = e.data.split('|');
        if (parts.length < 2) return;
        var status = parts[1];
        if (status === 'done')  setBadge('done');
        if (status === 'error') setBadge('error');
      });

      evtSource.addEventListener('agent-online', function(e) {
        refreshAgentList();
      });

      evtSource.addEventListener('agent-offline', function(e) {
        refreshAgentList();
      });

      evtSource.addEventListener('timing', function(e) {
        var parts = e.data.split('|');
        if (parts.length < 3) return;
        var kv   = parts[1];
        var type = parts[2];
        var eqIdx = kv.indexOf('=');
        var ms = eqIdx >= 0 ? kv.substring(eqIdx + 1) : kv;

        if (type === 'first_data')   document.getElementById('stat-network').textContent = ms + ' ms';
        if (type === 'agent_total')  document.getElementById('stat-agent').textContent = ms + ' ms';
        if (type === 'complete')     document.getElementById('stat-total').textContent = ms + ' ms';
      });

      evtSource.onerror = function() { setTimeout(connectSSE, 2000); };
    }

    /* ── Hamburger menu ───────────────────────────────────── */
    function toggleMenu() {
      document.getElementById('hamburger-menu').classList.toggle('open');
    }
    document.addEventListener('click', function(e) {
      var wrap = document.querySelector('.hamburger-wrap');
      if (wrap && !wrap.contains(e.target)) {
        document.getElementById('hamburger-menu').classList.remove('open');
      }
    });

    /* ── About modal ─────────────────────────────────────── */
    function showAbout() {
      document.getElementById('hamburger-menu').classList.remove('open');
      document.getElementById('about-modal').classList.add('open');
    }
    function closeAbout(e) {
      if (!e || e.target === document.getElementById('about-modal')) {
        document.getElementById('about-modal').classList.remove('open');
      }
    }

    /* ── Logout ──────────────────────────────────────────── */
    function doLogout() {
      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/logout');
      xhr.onload = function() { window.location.href = '/login'; };
      xhr.onerror = function() { window.location.href = '/login'; };
      xhr.send();
    }

    /* ── Load current user info ──────────────────────────── */
    function loadUserInfo() {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', '/api/me');
      xhr.onload = function() {
        if (xhr.status === 200) {
          var data = JSON.parse(xhr.responseText);
          document.getElementById('menu-user').textContent =
            'Signed in as ' + data.username + ' (' + data.role + ')';
          /* Hide settings link for non-admin */
          if (data.role !== 'admin') {
            var links = document.querySelectorAll('.hamburger-menu a[href="/settings"]');
            for (var i = 0; i < links.length; i++) {
              links[i].style.display = 'none';
            }
          }
        }
      };
      xhr.send();
    }

    /* ── Init ─────────────────────────────────────────────── */
    connectSSE();
    refreshAgentList();
    setInterval(refreshAgentList, 5000);
    loadUserInfo();
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
