// Chargen web UI HTML — compiled in its own translation unit to isolate
// the long raw string literal from MSVC's brace-matching in server.cpp.

// NOLINTBEGIN(cert-err58-cpp)
const char* const kChargenIndexHtml = R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Chargen Control</title>
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  <script src="https://unpkg.com/htmx-ext-sse@2.3.0/sse.js"></script>
  <style>
    :root {
      --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff;
      --green: #3fb950; --red: #f85149; --surface: #161b22;
      --border: #30363d; --mono: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
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
    .badge-stopped { background: var(--red); color: #fff; }
    .badge-running { background: var(--green); color: #fff; }
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
    .btn-clear { background: var(--surface); color: var(--fg); }
    .stats {
      display: flex; gap: 1.5rem; align-items: center;
      margin-left: auto; font-size: 0.8rem; color: #8b949e;
    }
    #terminal {
      flex: 1; overflow-y: auto; padding: 1rem 1.5rem;
      font-family: var(--mono); font-size: 0.8rem; line-height: 1.4;
      white-space: pre; background: var(--bg); color: var(--green);
    }
    footer {
      padding: 0.5rem 1.5rem; border-top: 1px solid var(--border);
      font-size: 0.75rem; color: #484f58;
    }
  </style>
</head>
<body>
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

  <footer>
    Yuzu Server &mdash; RFC 864 Character Generator &mdash; Output logged to server
  </footer>

  <script>
    const terminal  = document.getElementById('terminal');
    const badge     = document.getElementById('status-badge');
    const btnStart  = document.getElementById('btn-start');
    const btnStop   = document.getElementById('btn-stop');
    const lineCount = document.getElementById('line-count');
    const byteCount = document.getElementById('byte-count');

    let lines = 0;
    let bytes = 0;
    let evtSource = null;
    const MAX_LINES = 2000;

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

    function connectSSE() {
      if (evtSource) evtSource.close();
      evtSource = new EventSource('/events');

      evtSource.addEventListener('chargen', function(e) {
        lines++;
        bytes += e.data.length;
        lineCount.textContent = lines.toLocaleString();
        byteCount.textContent = bytes.toLocaleString();

        terminal.textContent += e.data + '\n';

        // Trim old lines to avoid unbounded memory
        if (lines > MAX_LINES) {
          const text = terminal.textContent;
          const idx = text.indexOf('\n');
          if (idx !== -1) terminal.textContent = text.substring(idx + 1);
        }

        // Auto-scroll
        terminal.scrollTop = terminal.scrollHeight;
      });

      evtSource.addEventListener('status', function(e) {
        setRunning(e.data === 'running');
      });

      evtSource.onerror = function() {
        setTimeout(connectSSE, 2000);
      };
    }

    // HTMX after-request hooks
    document.body.addEventListener('htmx:afterRequest', function(evt) {
      const path = evt.detail.pathInfo.requestPath;
      if (path === '/api/chargen/start') setRunning(true);
      if (path === '/api/chargen/stop')  setRunning(false);
    });

    connectSSE();
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
