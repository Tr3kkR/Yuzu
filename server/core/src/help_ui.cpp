// Help page — Phase 2 stub.
// Full HTMX help page will be implemented as part of the instruction system.

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kHelpHtml = R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — Help</title>
<link rel="stylesheet" href="/static/yuzu.css">
<style>
.help-content{max-width:800px;margin:1.5rem auto;padding:0 1.5rem}
h1{border-bottom:1px solid var(--border);padding-bottom:.5rem}
</style>
</head><body>

<nav class="nav-bar">
  <a href="/" class="nav-brand">
    <svg class="icon"><use href="/static/icons.svg#home"></use></svg> Yuzu
  </a>
  <a href="/" class="nav-link">Dashboard</a>
  <a href="/instructions" class="nav-link">Instructions</a>
  <a href="/settings" class="nav-link" id="nav-settings-link">Settings</a>
  <span class="nav-spacer"></span>
  <span class="nav-user" id="nav-user"></span>
  <button class="nav-logout" onclick="fetch('/logout',{method:'POST'}).then(function(){location='/login'})">Logout</button>
</nav>
<div class="context-bar" id="context-bar">
  <span class="context-role-badge" id="role-badge"></span>
  <span class="context-user" id="context-user"></span>
  <span class="context-spacer"></span>
  <button class="context-bell" title="Notifications">
    <svg class="icon"><use href="/static/icons.svg#bell"></use></svg>
  </button>
</div>

<div class="help-content">
<h1>Help</h1>
<p>Help page is under construction. See the <a href="/">dashboard</a>.</p>
</div>

<script>
fetch('/api/me').then(function(r){return r.json()}).then(function(d){
  document.getElementById('nav-user').textContent = d.username;
  var role = d.rbac_role || d.role;
  document.getElementById('role-badge').textContent = role;
  document.getElementById('context-user').textContent = d.username;
  document.body.setAttribute('data-role', role);
  if(d.role !== 'admin' && role !== 'Administrator' && role !== 'PlatformEngineer') {
    var sl = document.getElementById('nav-settings-link');
    if(sl) sl.style.display = 'none';
  }
});
</script>
</body></html>
)HTM";
// NOLINTEND(cert-err58-cpp)
