// Process-fetch web UI HTML — compiled in its own translation unit to isolate
// the long raw string literal from MSVC's brace-matching in server.cpp.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kProcfetchIndexHtml = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Process Fetch</title>
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
    .btn-fetch { background: var(--accent); color: #fff; border-color: var(--accent); }
    .btn-clear { background: var(--surface); color: var(--fg); }
    .stats {
      display: flex; gap: 1.5rem; align-items: center;
      margin-left: auto; font-size: 0.8rem; color: #8b949e;
    }
    .table-wrap {
      flex: 1; overflow-y: auto; padding: 0 1.5rem 1rem;
    }
    table {
      width: 100%; border-collapse: collapse; margin-top: 0.75rem;
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
      padding: 0.4rem 0.75rem; border-bottom: 1px solid var(--border);
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      max-width: 350px;
    }
    tbody tr:hover { background: rgba(88,166,255,0.06); }
    .col-pid  { width: 6rem; text-align: right; }
    .col-name { width: 14rem; }
    .col-path { min-width: 14rem; }
    .col-sha1 {
      font-family: var(--mono); font-size: 0.75rem;
      color: var(--accent); width: 22rem;
    }
    .empty-state {
      text-align: center; padding: 3rem 1rem; color: #484f58;
      font-size: 0.9rem;
    }
    footer {
      padding: 0.5rem 1.5rem; border-top: 1px solid var(--border);
      font-size: 0.75rem; color: #484f58;
      display: flex; justify-content: space-between;
    }
    footer a { color: var(--accent); text-decoration: none; }
    footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <header>
    <h1>Yuzu Process Fetch</h1>
    <span id="status-badge" class="badge badge-idle">IDLE</span>
  </header>

  <div class="controls">
    <button id="btn-fetch" class="btn-fetch"
            hx-post="/api/procfetch/fetch" hx-swap="none">
      Fetch Processes
    </button>
    <button id="btn-clear" class="btn-clear" onclick="clearTable()">
      Clear
    </button>
    <div class="stats">
      <span>Processes: <strong id="proc-count">0</strong></span>
    </div>
  </div>

  <div class="table-wrap">
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
    <span>Yuzu Server &mdash; Process enumeration with SHA-1 hashing &mdash; Data streamed from agent</span>
    <a href="/">Chargen Control</a>
  </footer>

  <script>
    const badge     = document.getElementById('status-badge');
    const btnFetch  = document.getElementById('btn-fetch');
    const procCount = document.getElementById('proc-count');
    const tableBody = document.getElementById('proc-table-body');
    const emptyRow  = document.getElementById('empty-row');

    let count = 0;
    let evtSource = null;

    function setBadge(state) {
      const map = {
        idle:     { text: 'IDLE',     cls: 'badge-idle' },
        fetching: { text: 'FETCHING', cls: 'badge-fetching' },
        done:     { text: 'DONE',     cls: 'badge-done' },
        error:    { text: 'ERROR',    cls: 'badge-error' },
      };
      const s = map[state] || map.idle;
      badge.textContent = s.text;
      badge.className   = 'badge ' + s.cls;
      btnFetch.disabled = (state === 'fetching');
    }

    function clearTable() {
      tableBody.innerHTML = '';
      emptyRow = null;
      count = 0;
      procCount.textContent = '0';
      setBadge('idle');
    }

    function escapeHtml(s) {
      const d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }

    function addProcess(line) {
      // Remove the empty-state row on first result
      var er = document.getElementById('empty-row');
      if (er) er.remove();

      // Format: pid|name|path|sha1
      const parts = line.split('|');
      if (parts.length < 4) return;
      const pid  = parts[0];
      const name = parts[1].replace(/\\\|/g, '|');
      const path = parts[2].replace(/\\\|/g, '|');
      const sha1 = parts[3];

      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="col-pid">'  + escapeHtml(pid)  + '</td>' +
        '<td class="col-name">' + escapeHtml(name) + '</td>' +
        '<td class="col-path" title="' + escapeHtml(path) + '">' + escapeHtml(path) + '</td>' +
        '<td class="col-sha1" title="' + escapeHtml(sha1) + '">' + escapeHtml(sha1) + '</td>';
      tableBody.appendChild(tr);

      count++;
      procCount.textContent = count.toLocaleString();
    }

    function connectSSE() {
      if (evtSource) evtSource.close();
      evtSource = new EventSource('/events');

      evtSource.addEventListener('procfetch', function(e) {
        addProcess(e.data);
      });

      evtSource.addEventListener('procfetch-status', function(e) {
        setBadge(e.data);
      });

      // Also listen for chargen events silently (shared SSE endpoint)
      evtSource.addEventListener('status', function() {});
      evtSource.addEventListener('chargen', function() {});

      evtSource.onerror = function() {
        setTimeout(connectSSE, 2000);
      };
    }

    document.body.addEventListener('htmx:afterRequest', function(evt) {
      if (evt.detail.pathInfo.requestPath === '/api/procfetch/fetch') {
        setBadge('fetching');
      }
    });

    connectSSE();
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
