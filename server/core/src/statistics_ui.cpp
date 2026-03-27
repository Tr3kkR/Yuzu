#include <cstddef>

namespace yuzu::server {

extern const char* const kStatisticsHtml;
extern const std::size_t kStatisticsHtmlLen;

const char* const kStatisticsHtml = R"html(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Statistics</title>
<link rel="stylesheet" href="/static/yuzu.css">
<script src="https://unpkg.com/htmx.org@2.0.4" crossorigin="anonymous"></script>
<style>
:root{--fg:#e0e0e0;--bg:#1a1a2e;--surface:#16213e;--border:#334155;--accent:#0f7dff;--green:#22c55e;--red:#ef4444;--yellow:#eab308}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,sans-serif;padding:1.5rem}
h1{font-size:1.4rem;margin-bottom:1rem}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem}
.card h2{font-size:.95rem;margin-bottom:.5rem;color:var(--accent)}
.big-num{font-size:2.2rem;font-weight:700}
.sub-text{font-size:.8rem;color:#94a3b8;margin-top:2px}
.bar{height:8px;background:var(--border);border-radius:4px;overflow:hidden;margin-top:.5rem}
.bar-fill{height:100%;border-radius:4px;transition:width .3s}
.bar-green{background:var(--green)}.bar-yellow{background:var(--yellow)}.bar-red{background:var(--red)}
table{width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.85rem}
th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);color:#94a3b8;font-weight:500}
td{padding:6px 8px;border-bottom:1px solid var(--border)}
a.back{color:var(--accent);text-decoration:none;font-size:.9rem}
</style>
</head>
<body>
<a class="back" href="/">&larr; Dashboard</a>
<h1>Statistics Dashboard</h1>
<div class="stats-grid">
  <div class="card" hx-get="/frag/stats-agents" hx-trigger="load, every 60s" hx-swap="innerHTML">
    <h2>Fleet Overview</h2><p class="sub-text">Loading...</p>
  </div>
  <div class="card" hx-get="/frag/stats-executions" hx-trigger="load, every 60s" hx-swap="innerHTML">
    <h2>Execution Metrics</h2><p class="sub-text">Loading...</p>
  </div>
  <div class="card" hx-get="/frag/stats-compliance" hx-trigger="load, every 60s" hx-swap="innerHTML">
    <h2>Compliance</h2><p class="sub-text">Loading...</p>
  </div>
  <div class="card" hx-get="/frag/stats-top-instructions" hx-trigger="load, every 60s" hx-swap="innerHTML">
    <h2>Top Instructions</h2><p class="sub-text">Loading...</p>
  </div>
  <div class="card" hx-get="/frag/stats-license" hx-trigger="load, every 60s" hx-swap="innerHTML">
    <h2>License</h2><p class="sub-text">Loading...</p>
  </div>
  <div class="card" hx-get="/frag/stats-system" hx-trigger="load, every 60s" hx-swap="innerHTML">
    <h2>System Health</h2><p class="sub-text">Loading...</p>
  </div>
</div>
</body>
</html>)html";

const std::size_t kStatisticsHtmlLen = __builtin_strlen(kStatisticsHtml);

} // namespace yuzu::server
