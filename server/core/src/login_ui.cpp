// Login page HTML — compiled in its own translation unit (MSVC raw-string limit).

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kLoginHtml =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Login</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <style>
    body {
      display: flex; align-items: center; justify-content: center;
      height: 100vh;
    }
    .login-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 0.75rem; padding: 2.5rem 2rem;
      width: 360px; text-align: center;
    }
    .login-card h1 {
      font-size: 1.5rem; font-weight: 600; margin-bottom: 0.25rem;
    }
    .login-card .subtitle {
      font-size: 0.8rem; color: #8b949e; margin-bottom: 1.5rem;
    }
    .field {
      margin-bottom: 1rem; text-align: left;
    }
    .field label {
      display: block; font-size: 0.8rem; font-weight: 600;
      color: #8b949e; margin-bottom: 0.3rem;
    }
    .field input {
      width: 100%; padding: 0.5rem 0.75rem;
      background: var(--bg); color: var(--fg);
      border: 1px solid var(--border); border-radius: 0.375rem;
      font-size: 0.875rem; font-family: var(--mono);
      outline: none;
    }
    .field input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 2px rgba(88,166,255,0.2);
    }
    .btn-login {
      width: 100%; padding: 0.6rem; font-size: 0.9rem; font-weight: 600;
      background: var(--accent); color: #fff; border: none;
      border-radius: 0.375rem; cursor: pointer; transition: opacity 0.15s;
      margin-top: 0.5rem;
    }
    .btn-login:hover { opacity: 0.85; }
    .btn-login:disabled { opacity: 0.4; cursor: not-allowed; }
    .error-msg {
      color: var(--red); font-size: 0.8rem; margin-top: 0.75rem;
      min-height: 1.2em;
    }
    .sso-section {
      margin-top: 1.5rem; padding-top: 1rem;
      border-top: 1px solid var(--border);
    }
    .btn-sso {
      width: 100%; padding: 0.5rem; font-size: 0.85rem; font-weight: 500;
      background: var(--surface); color: #484f58;
      border: 1px solid var(--border); border-radius: 0.375rem;
      cursor: not-allowed; opacity: 0.5;
      transition: opacity 0.15s, border-color 0.15s;
    }
    .btn-sso.enabled {
      color: var(--fg); cursor: pointer; opacity: 1;
      border-color: var(--accent);
    }
    .btn-sso.enabled:hover { background: #1c2128; }
    .sso-label {
      font-size: 0.7rem; color: #484f58; margin-top: 0.4rem;
    }
  </style>
</head>
<body>
  <div class="login-card">
    <h1>Yuzu</h1>
    <div class="subtitle">Sign in to the dashboard</div>

    <form id="login-form" onsubmit="doLogin(event)">
      <div class="field">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" autocomplete="username"
               autofocus required>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password"
               autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn-login" id="btn-login">Sign In</button>
      <div class="error-msg" id="error-msg"></div>
    </form>

    <div class="sso-section" id="sso-section">
      <button class="btn-sso" id="btn-sso" disabled>Sign in with SSO (OIDC)</button>
      <div class="sso-label" id="sso-label">Coming soon</div>
    </div>
  </div>

  <script>
    /*OIDC_CONFIG*/

    function doLogin(e) {
      e.preventDefault();
      var btn = document.getElementById('btn-login');
      var errEl = document.getElementById('error-msg');
      btn.disabled = true;
      errEl.textContent = '';

      var username = document.getElementById('username').value;
      var password = document.getElementById('password').value;

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/login');
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.onload = function() {
        if (xhr.status === 200) {
          window.location.href = '/';
        } else {
          try {
            var resp = JSON.parse(xhr.responseText);
            errEl.textContent = resp.error || 'Login failed';
          } catch(ex) {
            errEl.textContent = 'Login failed';
          }
          btn.disabled = false;
        }
      };
      xhr.onerror = function() {
        errEl.textContent = 'Network error';
        btn.disabled = false;
      };
      xhr.send('username=' + encodeURIComponent(username) +
               '&password=' + encodeURIComponent(password));
    }

    function startOidc() {
      window.location.href = '/auth/oidc/start';
    }

    // Enable SSO button if OIDC is configured (server injects window.OIDC_ENABLED)
    if (window.OIDC_ENABLED) {
      var ssoBtn = document.getElementById('btn-sso');
      ssoBtn.disabled = false;
      ssoBtn.classList.add('enabled');
      ssoBtn.textContent = 'Sign in with Microsoft Entra ID';
      ssoBtn.onclick = startOidc;
      document.getElementById('sso-label').textContent = '';
    }

    // Show OIDC error if redirected back with error param
    (function() {
      var params = new URLSearchParams(window.location.search);
      var err = params.get('error');
      if (err) {
        var errEl = document.getElementById('error-msg');
        var msgs = {
          'sso_denied': 'SSO sign-in was denied by the identity provider',
          'sso_failed': 'SSO authentication failed',
          'sso_invalid': 'Invalid SSO response'
        };
        errEl.textContent = msgs[err] || 'SSO error';
      }
    })();
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
