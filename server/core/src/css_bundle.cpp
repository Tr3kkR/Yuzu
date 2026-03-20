// Yuzu Design System — shared CSS bundle.
// Replaces duplicated :root blocks across dashboard, login, settings, and instruction UIs.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kYuzuCss = R"CSS(
/* Yuzu Design System — Dark Theme */
:root {
  /* Colors */
  --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff;
  --green: #3fb950; --red: #f85149; --yellow: #d29922;
  --surface: #161b22; --border: #30363d; --muted: #8b949e; --subtle: #484f58;

  /* Spacing (4px base) */
  --sp-1: 0.25rem; --sp-2: 0.5rem; --sp-3: 0.75rem; --sp-4: 1rem; --sp-6: 1.5rem;

  /* Typography */
  --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  --font-mono: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  --mono: var(--font-mono); /* backward-compat alias for existing page CSS */
  --text-xs: 0.65rem; --text-sm: 0.75rem; --text-base: 0.8rem; --text-lg: 1rem;

  /* Radii */
  --radius-sm: 0.3rem; --radius-md: 0.375rem; --radius-lg: 0.5rem;

  /* Role accent colors */
  --role-admin: #f85149; --role-platform: #d2a8ff; --role-operator: #58a6ff;
  --role-viewer: #8b949e; --role-token: #d29922; --role-service: #3fb950;
  --role-accent: var(--accent); /* default, overridden by data-role */
}

/* Role accent propagation */
[data-role="Administrator"] { --role-accent: var(--role-admin); }
[data-role="PlatformEngineer"] { --role-accent: var(--role-platform); }
[data-role="Operator"] { --role-accent: var(--role-operator); }
[data-role="Viewer"] { --role-accent: var(--role-viewer); }
[data-role="ApiTokenManager"] { --role-accent: var(--role-token); }
[data-role="ITServiceOwner"] { --role-accent: var(--role-service); }

/* Global reset */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font-sans); background: var(--bg); color: var(--fg); line-height: 1.5; }

/* Buttons */
.btn { height: 32px; padding: 0 var(--sp-4); font-size: var(--text-base); font-weight: 500;
       border-radius: var(--radius-md); border: 1px solid transparent; cursor: pointer;
       transition: opacity 0.15s; display: inline-flex; align-items: center; gap: var(--sp-2); }
.btn:hover:not(:disabled) { opacity: 0.85; }
.btn:disabled { opacity: 0.4; cursor: not-allowed; }
.btn:focus-visible { box-shadow: 0 0 0 2px rgba(88,166,255,0.4); outline: none; }
.btn-primary { background: var(--accent); color: #fff; }
.btn-success { background: var(--green); color: #fff; }
.btn-danger { background: var(--red); color: #fff; }
.btn-secondary { background: var(--surface); color: var(--fg); border-color: var(--border); }
.btn-ghost { background: transparent; color: var(--muted); }
.btn-sm { height: 28px; padding: 0 var(--sp-3); font-size: var(--text-sm); }

/* Cards */
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; }
.card-header { padding: var(--sp-3) var(--sp-4); border-bottom: 1px solid var(--border); font-weight: 600;
               display: flex; align-items: center; gap: var(--sp-2); }
.card-body { padding: var(--sp-4); }

/* Badges (translucent) */
.badge { display: inline-flex; align-items: center; height: 20px; padding: 0 var(--sp-2);
         border-radius: 9999px; font-size: var(--text-xs); font-weight: 600; white-space: nowrap; }
.badge-success { background: rgba(63,185,80,0.15); color: var(--green); }
.badge-danger { background: rgba(248,81,73,0.15); color: var(--red); }
.badge-warning { background: rgba(210,153,34,0.15); color: var(--yellow); }
.badge-info { background: rgba(88,166,255,0.15); color: var(--accent); }
.badge-neutral { background: rgba(139,148,158,0.15); color: var(--muted); }

/* Tables */
.data-table { width: 100%; border-collapse: collapse; font-size: var(--text-base); }
.data-table th { text-align: left; padding: var(--sp-2) var(--sp-3); font-size: var(--text-sm);
                 font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em;
                 border-bottom: 2px solid var(--border); position: sticky; top: 0; background: var(--surface); }
.data-table td { padding: var(--sp-2) var(--sp-3); border-bottom: 1px solid var(--border); }
.data-table tr:hover { background: rgba(88,166,255,0.06); }

/* Forms */
.input { height: 32px; padding: 0 var(--sp-3); background: var(--bg); color: var(--fg);
         border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: var(--text-base);
         font-family: var(--font-mono); outline: none; transition: border-color 0.15s, box-shadow 0.15s; }
.input:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(88,166,255,0.4); }
.input::placeholder { color: var(--subtle); }

/* Toasts */
.toast-container { position: fixed; top: var(--sp-4); right: var(--sp-4); z-index: 5000;
                   display: flex; flex-direction: column; gap: var(--sp-2); pointer-events: none; }
.toast { min-width: 320px; max-width: 480px; padding: var(--sp-3) var(--sp-4); background: var(--surface);
         border: 1px solid var(--border); border-radius: var(--radius-md);
         box-shadow: 0 8px 24px rgba(0,0,0,0.4); pointer-events: auto;
         animation: toast-in 200ms ease-out; }
.toast-success { border-left: 3px solid var(--green); }
.toast-error { border-left: 3px solid var(--red); }
.toast-warning { border-left: 3px solid var(--yellow); }
.toast-info { border-left: 3px solid var(--accent); }
@keyframes toast-in { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }

/* Alerts */
.alert { padding: var(--sp-3) var(--sp-4); border-radius: var(--radius-md); font-size: var(--text-base);
         display: flex; align-items: flex-start; gap: var(--sp-3); margin-bottom: var(--sp-4); }
.alert-error { background: #3d1418; border: 1px solid #6e2b2d; color: var(--red); }
.alert-success { background: #0d2818; border: 1px solid #1a4731; color: var(--green); }
.alert-warning { background: #2d2000; border: 1px solid #4d3800; color: var(--yellow); }

/* Icons (inline SVG via sprite) */
.icon { width: 16px; height: 16px; fill: none; stroke: currentColor; stroke-width: 2;
        stroke-linecap: round; stroke-linejoin: round; vertical-align: middle; }
.icon-lg { width: 20px; height: 20px; }
.icon-xl { width: 24px; height: 24px; }

/* Nav bar (to be used in Wave B) */
.nav-bar { height: 40px; background: var(--surface); border-bottom: 1px solid var(--border);
           display: flex; align-items: center; padding: 0 var(--sp-4); gap: var(--sp-4); }
.nav-brand { color: var(--fg); text-decoration: none; font-weight: 700; font-size: var(--text-lg);
             display: flex; align-items: center; gap: var(--sp-2); }
.nav-link { color: var(--muted); text-decoration: none; font-size: var(--text-sm); padding: var(--sp-2) 0;
            border-bottom: 2px solid transparent; transition: color 0.15s; }
.nav-link:hover { color: var(--fg); }
.nav-link.active { color: var(--fg); border-bottom-color: var(--role-accent); }
.nav-spacer { flex: 1; }
.nav-user { font-size: var(--text-sm); color: var(--muted); display: flex; align-items: center; gap: var(--sp-2); }
.nav-logout { background: transparent; border: 1px solid var(--border); color: var(--muted);
              padding: var(--sp-1) var(--sp-3); border-radius: var(--radius-sm); cursor: pointer;
              font-size: var(--text-sm); }

/* Context bar (to be used in Wave B) */
.context-bar { height: 32px; background: var(--bg); border-bottom: 2px solid var(--role-accent);
               display: flex; align-items: center; padding: 0 var(--sp-4); gap: var(--sp-3); }
.context-role-badge { font-size: var(--text-xs); font-weight: 700; text-transform: uppercase;
                      letter-spacing: 0.08em; padding: 2px var(--sp-2); border-radius: 9999px;
                      background: var(--role-accent); color: #fff; }
.context-user { font-size: var(--text-sm); color: var(--muted); }
.context-spacer { flex: 1; }
.context-bell { background: transparent; border: none; color: var(--muted); cursor: pointer; padding: var(--sp-1); }
.context-bell:hover { color: var(--fg); }

/* Responsive */
@media (max-width: 1440px) {
  .history { width: 180px !important; }
  .scope { width: 220px !important; }
}
@media (max-width: 1280px) {
  .main-grid { grid-template-columns: 1fr !important; }
  .history, .scope { display: none !important; }
}

/* Reduced motion */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition-duration: 0ms !important; animation-duration: 0ms !important; }
}
)CSS";
// NOLINTEND(cert-err58-cpp)
