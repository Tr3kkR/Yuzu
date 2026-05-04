#include <cstddef>

namespace yuzu::server {

extern const char* const kTopologyHtml;
extern const std::size_t kTopologyHtmlLen;

const char* const kTopologyHtml = R"html(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — System Topology</title>
<link rel="stylesheet" href="/static/yuzu.css">
<script src="/static/htmx.js"></script>
<style>
/* Inherits Yuzu design-system tokens from /static/yuzu.css — no local :root override. */
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:var(--mds-font-family-default);padding:1.5rem}
h1{font-size:1.4rem;margin-bottom:1rem}
.topo-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-bottom:1.5rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem}
.card h2{font-size:1rem;margin-bottom:.5rem;color:var(--accent)}
.stat{font-size:2rem;font-weight:700}
.stat-label{font-size:.8rem;color:var(--mds-color-theme-text-tertiary)}
.tree ul{list-style:none;padding-left:1.2rem}
.tree li{position:relative;padding:4px 0}
.tree li::before{content:"";position:absolute;left:-1rem;top:0;border-left:1px solid var(--border);height:100%}
.gw-list{display:flex;flex-wrap:wrap;gap:.5rem}
.gw-badge{background:var(--surface);border:1px solid var(--green);border-radius:4px;padding:4px 8px;font-size:.85rem}
.gw-badge.offline{border-color:var(--red)}
.os-bar{display:flex;height:24px;border-radius:4px;overflow:hidden;margin-top:.5rem}
.os-seg{display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:600;color:var(--mds-color-text-on-accent)}
/* OS swatches keep their brand hues (Windows blue, Ubuntu orange,
   macOS grey) — not part of the Yuzu design palette. */
.os-win{background:#0078d4}.os-linux{background:#e95420}.os-darwin{background:#6e7681}
a.back{color:var(--accent);text-decoration:none;font-size:.9rem}
</style>
</head>
<body>
<a class="back" href="/">&larr; Dashboard</a>
<h1>System Topology</h1>
<div hx-get="/frag/topology-data" hx-trigger="load, every 30s" hx-swap="innerHTML">
  <p style="color:var(--mds-color-theme-text-tertiary)">Loading topology...</p>
</div>
</body>
</html>)html";

const std::size_t kTopologyHtmlLen = __builtin_strlen(kTopologyHtml);

} // namespace yuzu::server
