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
      font-size: 0.8rem; color: var(--mds-color-theme-text-tertiary); margin-bottom: 1.5rem;
    }
    .field {
      margin-bottom: 1rem; text-align: left;
    }
    .field label {
      display: block; font-size: 0.8rem; font-weight: 600;
      color: var(--mds-color-theme-text-tertiary); margin-bottom: 0.3rem;
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
      box-shadow: 0 0 0 2px var(--mds-color-state-selected);
    }
    .btn-login {
      width: 100%; padding: 0.6rem; font-size: 0.9rem; font-weight: 600;
      background: var(--accent); color: var(--mds-color-text-on-accent); border: none;
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
      background: var(--surface); color: var(--mds-color-theme-outline-secondary);
      border: 1px solid var(--border); border-radius: 0.375rem;
      cursor: not-allowed; opacity: 0.5;
      transition: opacity 0.15s, border-color 0.15s;
    }
    .btn-sso.enabled {
      color: var(--fg); cursor: pointer; opacity: 1;
      border-color: var(--accent);
    }
    .btn-sso.enabled:hover { background: var(--mds-color-theme-background-solid-secondary); }
    .sso-label {
      font-size: 0.7rem; color: var(--mds-color-theme-outline-secondary); margin-top: 0.4rem;
    }
    .enroll-secret {
      text-align: left; background: var(--bg); border: 1px solid var(--border);
      border-radius: 0.375rem; padding: 0.75rem; margin-bottom: 1rem;
      font-size: 0.75rem;
    }
    .enroll-secret-label {
      font-size: 0.7rem; color: var(--mds-color-theme-text-tertiary); margin-bottom: 0.2rem;
    }
    .enroll-secret code {
      font-family: var(--mono); color: var(--fg); font-size: 0.8rem;
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
               autocapitalize="none" autocorrect="off" spellcheck="false"
               aria-label="Username" autofocus required>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password"
               aria-label="Password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn-login" id="btn-login" aria-label="Sign in">Sign In</button>
      <div class="error-msg" id="error-msg" role="alert" aria-live="polite"></div>
    </form>

    <form id="mfa-form" onsubmit="doMfa(event)" style="display:none">
      <div class="subtitle">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</div>
      <input type="hidden" id="mfa-pending-token">
      <div class="field">
        <label for="mfa-code">Verification code</label>
        <input type="text" id="mfa-code" name="code" autocomplete="one-time-code"
               autocapitalize="none" autocorrect="off" spellcheck="false"
               inputmode="numeric" autofocus required>
      </div>
      <button type="submit" class="btn-login" id="btn-mfa" aria-label="Verify">Verify</button>
      <div class="error-msg" id="mfa-error-msg" role="alert" aria-live="polite"></div>
    </form>

    <form id="enroll-form" onsubmit="doEnroll(event)" style="display:none">
      <div class="subtitle">Multi-factor authentication is required. Scan this with your
        authenticator app, then enter the 6-digit code it shows to finish signing in.</div>
      <input type="hidden" id="enroll-pending-token">
      <div id="enroll-qr" style="display:none;justify-content:center;margin:0 0 0.5rem 0">
        <div style="background:#fff;padding:8px;border-radius:6px;line-height:0"></div>
      </div>
      <div id="enroll-qr-hint" style="display:none;font-size:0.7rem;
        color:var(--mds-color-theme-text-tertiary);text-align:center;margin-bottom:0.5rem">
        Can't scan? Enter the secret below manually.</div>
      <div class="enroll-secret">
        <div class="enroll-secret-label">Base32 secret (manual entry)</div>
        <code id="enroll-secret"></code>
        <div class="enroll-secret-label" style="margin-top:0.5rem">otpauth URI</div>
        <code id="enroll-otpauth" style="display:block;word-break:break-all"></code>
      </div>
      <div class="field">
        <label for="enroll-code">Verification code</label>
        <input type="text" id="enroll-code" name="code" autocomplete="one-time-code"
               autocapitalize="none" autocorrect="off" spellcheck="false"
               inputmode="numeric" required>
      </div>
      <button type="submit" class="btn-login" id="btn-enroll" aria-label="Enable and sign in">Enable &amp; Sign In</button>
      <div class="error-msg" id="enroll-error-msg" role="alert" aria-live="polite"></div>
    </form>

    <div id="recovery-panel" style="display:none;text-align:left">
      <div class="subtitle" style="text-align:center">Save these recovery codes now — each can be
        used once if you lose your authenticator.</div>
      <ul id="recovery-list" style="font-family:var(--mono);font-size:0.85rem;
        background:var(--bg);border:1px solid var(--border);border-radius:0.375rem;
        padding:0.75rem 0.75rem 0.75rem 1.75rem;margin:0 0 1rem 0"></ul>
      <button type="button" class="btn-login" onclick="window.location.href='/'"
              aria-label="Continue to dashboard">I've saved them — Continue</button>
    </div>

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
          return;
        }
        if (xhr.status === 202) {
          try {
            var resp = JSON.parse(xhr.responseText);
            var loginForm = document.getElementById('login-form');
            var ssoSection = document.getElementById('sso-section');
            // Already-enrolled user — swap to the TOTP challenge form.
            if (resp && resp.status === 'mfa_required' && resp.mfa_pending_token) {
              document.getElementById('mfa-pending-token').value = resp.mfa_pending_token;
              loginForm.style.display = 'none';
              if (ssoSection) ssoSection.style.display = 'none';
              document.getElementById('mfa-form').style.display = '';
              document.getElementById('mfa-code').focus();
              return;
            }
            // Enforcement requires enrollment — swap to the enroll form.
            if (resp && resp.status === 'mfa_enrollment_required' && resp.mfa_pending_token) {
              document.getElementById('enroll-pending-token').value = resp.mfa_pending_token;
              document.getElementById('enroll-otpauth').textContent = resp.otpauth_uri || '';
              document.getElementById('enroll-secret').textContent = resp.secret_base32 || '';
              // qr_svg is server-rendered (qrcodegen over our own otpauth URI),
              // not user input — safe to inject as markup. Empty → keep hidden,
              // the manual secret above is the fallback.
              var qrWrap = document.getElementById('enroll-qr');
              var qrHint = document.getElementById('enroll-qr-hint');
              if (resp.qr_svg) {
                qrWrap.firstElementChild.innerHTML = resp.qr_svg;
                qrWrap.style.display = 'flex';
                qrHint.style.display = '';
              } else {
                qrWrap.style.display = 'none';
                qrHint.style.display = 'none';
              }
              loginForm.style.display = 'none';
              if (ssoSection) ssoSection.style.display = 'none';
              document.getElementById('enroll-form').style.display = '';
              document.getElementById('enroll-code').focus();
              return;
            }
          } catch(ex) { /* fall through to error display */ }
          errEl.textContent = 'Login failed (' + xhr.status + ')';
          btn.disabled = false;
          return;
        }
        // Server returns the structured envelope:
        //   {"error":{"code":N,"message":"..."},"meta":{...}}
        // Pre-envelope responses used a flat string "error".
        var msg = '';
        try {
          var resp = JSON.parse(xhr.responseText);
          if (resp && resp.error) {
            if (typeof resp.error === 'string') {
              msg = resp.error;
            } else if (typeof resp.error === 'object' && resp.error.message) {
              msg = resp.error.message;
            }
          }
        } catch(ex) { /* fall through to default */ }
        if (!msg) {
          msg = (xhr.status === 401) ? 'Invalid username or password'
                                     : 'Login failed (' + xhr.status + ')';
        }
        errEl.textContent = msg;
        btn.disabled = false;
      };
      xhr.onerror = function() {
        errEl.textContent = 'Network error';
        btn.disabled = false;
      };
      xhr.send('username=' + encodeURIComponent(username) +
               '&password=' + encodeURIComponent(password));
    }

    function doMfa(e) {
      e.preventDefault();
      var btn = document.getElementById('btn-mfa');
      var errEl = document.getElementById('mfa-error-msg');
      btn.disabled = true;
      errEl.textContent = '';

      var pending = document.getElementById('mfa-pending-token').value;
      var code = document.getElementById('mfa-code').value;

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/login/mfa');
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.onload = function() {
        if (xhr.status === 200) {
          window.location.href = '/';
          return;
        }
        var msg = '';
        try {
          var resp = JSON.parse(xhr.responseText);
          if (resp && resp.error && resp.error.message) {
            msg = resp.error.message;
          }
        } catch(ex) { /* default below */ }
        if (!msg) {
          msg = 'Invalid verification code';
        }
        errEl.textContent = msg;
        btn.disabled = false;
        document.getElementById('mfa-code').focus();
        document.getElementById('mfa-code').select();
      };
      xhr.onerror = function() {
        errEl.textContent = 'Network error';
        btn.disabled = false;
      };
      xhr.send('mfa_pending_token=' + encodeURIComponent(pending) +
               '&code=' + encodeURIComponent(code));
    }

    function doEnroll(e) {
      e.preventDefault();
      var btn = document.getElementById('btn-enroll');
      var errEl = document.getElementById('enroll-error-msg');
      btn.disabled = true;
      errEl.textContent = '';

      var pending = document.getElementById('enroll-pending-token').value;
      var code = document.getElementById('enroll-code').value;

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/login/mfa/enroll');
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.onload = function() {
        if (xhr.status === 200) {
          // Enrollment complete — session is set. Reveal recovery codes
          // before letting the operator continue to the dashboard.
          var codes = [];
          try {
            var resp = JSON.parse(xhr.responseText);
            if (resp && Array.isArray(resp.recovery_codes)) codes = resp.recovery_codes;
          } catch(ex) { /* no codes to show */ }
          if (codes.length) {
            var list = document.getElementById('recovery-list');
            list.innerHTML = '';
            codes.forEach(function(c) {
              var li = document.createElement('li');
              li.textContent = c;
              list.appendChild(li);
            });
            document.getElementById('enroll-form').style.display = 'none';
            document.getElementById('recovery-panel').style.display = '';
          } else {
            window.location.href = '/';
          }
          return;
        }
        var msg = '';
        try {
          var resp = JSON.parse(xhr.responseText);
          if (resp && resp.error && resp.error.message) msg = resp.error.message;
        } catch(ex) { /* default below */ }
        if (!msg) msg = 'Invalid verification code';
        errEl.textContent = msg;
        btn.disabled = false;
        document.getElementById('enroll-code').focus();
        document.getElementById('enroll-code').select();
      };
      xhr.onerror = function() {
        errEl.textContent = 'Network error';
        btn.disabled = false;
      };
      xhr.send('mfa_pending_token=' + encodeURIComponent(pending) +
               '&code=' + encodeURIComponent(code));
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
