// Chargen web UI HTML — compiled in its own translation unit to isolate
// the long raw string literal from MSVC's brace-matching in server.cpp.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kChargenIndexHtml = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Control Panel</title>
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  <script src="https://unpkg.com/htmx-ext-sse@2.3.0/sse.js"></script>
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
      display: flex; flex-direction: column; height: 100vh;
    }
    header {
      display: flex; align-items: center; gap: 1rem;
      padding: 1rem 1.5rem; border-bottom: 1px solid var(--border);
    }
    header h1 { font-size: 1.25rem; font-weight: 600; }
    .badge {
      font-size: 0.75rem; padding: 0.15rem 0.5rem;
      border-radius: 1rem; font-weight: 600;
    }
    .badge-stopped  { background: var(--red); color: #fff; }
    .badge-running  { background: var(--green); color: #fff; }
    .badge-idle     { background: #484f58; color: #fff; }
    .badge-fetching { background: var(--yellow); color: #000; }
    .badge-done     { background: var(--green); color: #fff; }
    .badge-error    { background: var(--red); color: #fff; }
    .controls {
      display: flex; gap: 0.75rem;
      padding: 0.75rem 1.5rem; border-bottom: 1px solid var(--border);
    }
    button {
      font-size: 0.875rem; padding: 0.4rem 1rem;
      border: 1px solid var(--border); border-radius: 0.375rem;
      cursor: pointer; font-weight: 500; transition: opacity 0.15s;
    }
    button:hover { opacity: 0.85; }
    button:disabled { opacity: 0.4; cursor: not-allowed; }
    .btn-start { background: var(--green); color: #fff; border-color: var(--green); }
    .btn-stop  { background: var(--red);   color: #fff; border-color: var(--red); }
    .btn-fetch { background: var(--accent); color: #fff; border-color: var(--accent); }
    .btn-clear { background: var(--surface); color: var(--fg); }
    .stats {
      display: flex; gap: 1.5rem; align-items: center;
      margin-left: auto; font-size: 0.8rem; color: #8b949e;
    }
    .section-header {
      display: flex; align-items: center; gap: 0.75rem;
      padding: 0.6rem 1.5rem; border-bottom: 1px solid var(--border);
      background: var(--surface);
    }
    .section-header h2 { font-size: 0.95rem; font-weight: 600; }
    #terminal {
      flex: 1; overflow-y: auto; padding: 1rem 1.5rem;
      font-family: var(--mono); font-size: 0.8rem; line-height: 1.4;
      white-space: pre; background: var(--bg); color: var(--green);
      min-height: 120px;
    }
    .proc-table-wrap {
      flex: 1; overflow-y: auto; min-height: 120px;
    }
    table {
      width: 100%; border-collapse: collapse;
      font-size: 0.8rem;
    }
    thead th {
      position: sticky; top: 0; background: var(--surface);
      text-align: left; padding: 0.5rem 0.75rem;
      border-bottom: 2px solid var(--border); font-weight: 600;
      color: #8b949e; text-transform: uppercase; font-size: 0.7rem;
      letter-spacing: 0.05em;
    }
    tbody td {
      padding: 0.35rem 0.75rem; border-bottom: 1px solid var(--border);
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      max-width: 350px;
    }
    tbody tr:hover { background: rgba(88,166,255,0.06); }
    .col-pid  { width: 5rem; text-align: right; }
    .col-name { width: 12rem; }
    .col-path { min-width: 14rem; }
    .col-sha1 {
      font-family: var(--mono); font-size: 0.75rem;
      color: var(--accent); width: 20rem;
    }
    .empty-state {
      text-align: center; padding: 2rem 1rem; color: #484f58;
      font-size: 0.85rem;
    }
    footer {
      padding: 0.5rem 1.5rem; border-top: 1px solid var(--border);
      font-size: 0.75rem; color: #484f58;
    }
  </style>
</head>
<body>
  <!-- Chargen Section -->
  <header>
    <h1>Yuzu Chargen</h1>
    <span id="status-badge" class="badge badge-stopped">STOPPED</span>
  </header>

  <div class="controls">
    <button id="btn-start" class="btn-start"
            hx-post="/api/chargen/start" hx-swap="none">
      Start
    </button>
    <button id="btn-stop" class="btn-stop" disabled
            hx-post="/api/chargen/stop" hx-swap="none">
      Stop
    </button>
    <button id="btn-clear" class="btn-clear" onclick="clearTerminal()">
      Clear
    </button>
    <div class="stats">
      <span>Lines: <strong id="line-count">0</strong></span>
      <span>Bytes: <strong id="byte-count">0</strong></span>
    </div>
  </div>

  <div id="terminal"></div>

  <!-- Process Fetch Section -->
  <div class="section-header">
    <h2>Process Fetch</h2>
    <span id="pf-badge" class="badge badge-idle">IDLE</span>
  </div>

  <div class="controls">
    <button id="btn-fetch" class="btn-fetch"
            hx-post="/api/procfetch/fetch" hx-swap="none">
      Fetch Processes
    </button>
    <button class="btn-clear" onclick="clearProcTable()">
      Clear
    </button>
    <div class="stats">
      <span>Processes: <strong id="proc-count">0</strong></span>
    </div>
  </div>

  <div class="proc-table-wrap">
    <table>
      <thead>
        <tr>
          <th class="col-pid">PID</th>
          <th class="col-name">Name</th>
          <th class="col-path">Path</th>
          <th class="col-sha1">SHA-1</th>
        </tr>
      </thead>
      <tbody id="proc-table-body">
        <tr id="empty-row"><td colspan="4" class="empty-state">
          Click <strong>Fetch Processes</strong> to enumerate running processes.
        </td></tr>
      </tbody>
    </table>
  </div>

  <footer>
    Yuzu Server &mdash; Chargen + Process Fetch &mdash; Data streamed from agent
  </footer>

  <script>
    /* -- Chargen state ------------------------------------------------ */
    var terminal  = document.getElementById('terminal');
    var badge     = document.getElementById('status-badge');
    var btnStart  = document.getElementById('btn-start');
    var btnStop   = document.getElementById('btn-stop');
    var lineCount = document.getElementById('line-count');
    var byteCount = document.getElementById('byte-count');

    var lines = 0;
    var bytes = 0;
    var evtSource = null;
    var MAX_LINES = 2000;

    function setRunning(on) {
      badge.textContent = on ? 'RUNNING' : 'STOPPED';
      badge.className   = 'badge ' + (on ? 'badge-running' : 'badge-stopped');
      btnStart.disabled = on;
      btnStop.disabled  = !on;
    }

    function clearTerminal() {
      terminal.textContent = '';
      lines = 0; bytes = 0;
      lineCount.textContent = '0';
      byteCount.textContent = '0';
    }

    /* -- Process Fetch state ------------------------------------------ */
    var pfBadge    = document.getElementById('pf-badge');
    var btnFetch   = document.getElementById('btn-fetch');
    var procCount  = document.getElementById('proc-count');
    var procBody   = document.getElementById('proc-table-body');
    var procTotal  = 0;

    function setPfBadge(state) {
      var map = {
        idle:     { text: 'IDLE',     cls: 'badge-idle' },
        fetching: { text: 'FETCHING', cls: 'badge-fetching' },
        done:     { text: 'DONE',     cls: 'badge-done' },
        error:    { text: 'ERROR',    cls: 'badge-error' }
      };
      var s = map[state] || map.idle;
      pfBadge.textContent = s.text;
      pfBadge.className   = 'badge ' + s.cls;
      btnFetch.disabled = (state === 'fetching');
    }

    function clearProcTable() {
      procBody.innerHTML = '';
      procTotal = 0;
      procCount.textContent = '0';
      setPfBadge('idle');
    }

    function escapeHtml(s) {
      var d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }

    function addProcess(line) {
      var er = document.getElementById('empty-row');
      if (er) er.remove();

      var parts = line.split('|');
      if (parts.length < 4) return;
      var pid  = parts[0];
      var name = parts[1].replace(/\\\|/g, '|');
      var path = parts[2].replace(/\\\|/g, '|');
      var sha1 = parts[3];

      var tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="col-pid">'  + escapeHtml(pid)  + '</td>' +
        '<td class="col-name">' + escapeHtml(name) + '</td>' +
        '<td class="col-path" title="' + escapeHtml(path) + '">' + escapeHtml(path) + '</td>' +
        '<td class="col-sha1" title="' + escapeHtml(sha1) + '">' + escapeHtml(sha1) + '</td>';
      procBody.appendChild(tr);

      procTotal++;
      procCount.textContent = procTotal.toLocaleString();
    }

    /* -- SSE ---------------------------------------------------------- */
    function connectSSE() {
      if (evtSource) evtSource.close();
      evtSource = new EventSource('/events');

      evtSource.addEventListener('chargen', function(e) {
        lines++;
        bytes += e.data.length;
        lineCount.textContent = lines.toLocaleString();
        byteCount.textContent = bytes.toLocaleString();

        terminal.textContent += e.data + '\n';

        if (lines > MAX_LINES) {
          var text = terminal.textContent;
          var idx = text.indexOf('\n');
          if (idx !== -1) terminal.textContent = text.substring(idx + 1);
        }

        terminal.scrollTop = terminal.scrollHeight;
      });

      evtSource.addEventListener('status', function(e) {
        setRunning(e.data === 'running');
      });

      evtSource.addEventListener('procfetch', function(e) {
        addProcess(e.data);
      });

      evtSource.addEventListener('procfetch-status', function(e) {
        setPfBadge(e.data);
      });

      evtSource.onerror = function() {
        setTimeout(connectSSE, 2000);
      };
    }

    /* -- HTMX hooks --------------------------------------------------- */
    document.body.addEventListener('htmx:afterRequest', function(evt) {
      var path = evt.detail.pathInfo.requestPath;
      if (path === '/api/chargen/start') setRunning(true);
      if (path === '/api/chargen/stop')  setRunning(false);
      if (path === '/api/procfetch/fetch') setPfBadge('fetching');
    });

    connectSSE();
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
