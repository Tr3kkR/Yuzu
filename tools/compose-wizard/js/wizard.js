/* ── Wizard Navigation & UI Logic ── */

let currentStep = 1;

function goStep(n) {
  // Hide current
  document.getElementById(`step-${currentStep}`).classList.remove('active');
  document.querySelector(`.step[data-step="${currentStep}"]`).classList.remove('active');

  currentStep = n;

  // Show new
  document.getElementById(`step-${currentStep}`).classList.add('active');
  document.querySelector(`.step[data-step="${currentStep}"]`).classList.add('active');

  // If review step, build summary
  if (n === 6) buildReview();

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Step nav click handlers
document.querySelectorAll('.step').forEach(btn => {
  btn.addEventListener('click', () => {
    const s = parseInt(btn.dataset.step);
    if (s <= currentStep) goStep(s); // only allow going back, not skipping ahead
  });
});

// Toggle visibility for optional sections
document.getElementById('enable-tls').addEventListener('change', e => {
  document.querySelectorAll('.tls-field').forEach(f => f.style.display = e.target.checked ? '' : 'none');
});

document.getElementById('include-clickhouse').addEventListener('change', e => {
  document.getElementById('clickhouse-fields').style.display = e.target.checked ? '' : 'none';
});

document.getElementById('include-prometheus').addEventListener('change', e => {
  document.getElementById('prom-port-field').style.display = e.target.checked ? '' : 'none';
});

document.getElementById('include-grafana').addEventListener('change', e => {
  document.getElementById('grafana-fields').style.display = e.target.checked ? '' : 'none';
});

document.getElementById('include-gateway').addEventListener('change', e => {
  document.getElementById('gateway-fields').style.display = e.target.checked ? '' : 'none';
});

// ── Helpers ──

function val(id) { return document.getElementById(id).value.trim(); }
function num(id) { return parseInt(document.getElementById(id).value) || 0; }
function chk(id) { return document.getElementById(id).checked; }

// ── Admin password hash ──
// Yuzu uses: username:password:salt in a specific format
// Format: user:pass:salt_hash where salt_hash = sha256(username + ":" + password + ":" + salt)
// The compose file uses a pre-computed hash. We'll note that users need to generate one.
function computeAdminHash(user, pass) {
  // The default in the original compose is:
  // admin:admin:ab3585560da45a7b7da0a220c922dd72:25e957743ebefd48d938b30cdd117ef4487897da209e0e8883dd473363dceb8a
  // This is user:salt:md5_of_salt:sha256_of_salt_pass
  // For simplicity, we'll use a random salt and compute the hashes
  // NOTE: In production, users should generate this via yuzu-server CLI
  const salt = 'auto' + Math.random().toString(36).slice(2, 10);
  // We can't do SHA-256 synchronously in browser without SubtleCrypto (async)
  // So we'll provide a placeholder and a note
  return `${user}:${pass}:${salt}:RUN_yuzu-server_hash_command`;
}

// ── Port conflict detection ──
const COMMON_PORTS = {
  80: 'HTTP',
  443: 'HTTPS',
  3000: 'Grafana (default)',
  3306: 'MySQL',
  5000: 'Flask/Python',
  5432: 'PostgreSQL',
  6379: 'Redis',
  8080: 'Common app server',
  8123: 'ClickHouse HTTP (default)',
  9000: 'ClickHouse Native (default)',
  9090: 'Prometheus (default)',
  27017: 'MongoDB',
};

function detectPortConflicts() {
  const ports = {};
  if (chk('include-clickhouse') || true) {
    // Always include server ports
    ports[num('dashboard-port')] = 'Yuzu Dashboard';
    ports[num('grpc-port')] = 'Yuzu Agent gRPC';
    ports[num('mgmt-port')] = 'Yuzu Management gRPC';
    ports[num('gateway-upstream-port')] = 'Yuzu Gateway Upstream';
  }
  if (chk('include-clickhouse')) {
    ports[num('ch-http-port')] = 'ClickHouse HTTP';
    ports[num('ch-native-port')] = 'ClickHouse Native';
  }
  if (chk('include-prometheus')) {
    ports[num('prom-port')] = 'Prometheus';
  }
  if (chk('include-grafana')) {
    ports[num('grafana-port')] = 'Grafana';
  }
  if (chk('include-gateway')) {
    ports[num('gw-agent-port')] = 'Gateway Agent';
    ports[num('gw-mgmt-port')] = 'Gateway Management';
    ports[num('gw-health-port')] = 'Gateway Health';
    ports[num('gw-metrics-port')] = 'Gateway Metrics';
  }

  const warnings = [];
  const seen = {};

  for (const [port, label] of Object.entries(ports)) {
    if (seen[port]) {
      warnings.push(`⚠️ Port ${port} used by both "${seen[port]}" and "${label}"`);
    }
    seen[port] = label;

    if (COMMON_PORTS[port] && !ports[port]?.includes(COMMON_PORTS[port].split(' ')[0])) {
      warnings.push(`ℹ️ Port ${port} is commonly used by ${COMMON_PORTS[port]}`);
    }
  }

  return warnings;
}

// ── Review Summary ──
function buildReview() {
  const items = [
    ['Yuzu Version', val('yuzu-version')],
    ['Admin User', val('admin-user')],
    ['Dashboard Port', num('dashboard-port')],
    ['Agent gRPC Port', num('grpc-port')],
    ['TLS', chk('enable-tls') ? '✅ Enabled' : '❌ Disabled'],
    ['ClickHouse', chk('include-clickhouse') ? '✅ Included' : '❌ Skipped'],
    ['Prometheus', chk('include-prometheus') ? '✅ Included' : '❌ Skipped'],
    ['Grafana', chk('include-grafana') ? '✅ Included' : '❌ Skipped'],
    ['Gateway', chk('include-gateway') ? '✅ Included' : '❌ Skipped'],
    ['Named Volumes', chk('persistent-volumes') ? '✅ Yes' : '❌ No'],
  ];

  let html = '<div class="review-grid">';
  for (const [label, value] of items) {
    html += `<div class="review-item"><span class="review-label">${label}</span><span class="review-value">${value}</span></div>`;
  }
  html += '</div>';
  document.getElementById('review-summary').innerHTML = html;

  // Port warnings
  const warnings = detectPortConflicts();
  const warnEl = document.getElementById('port-warnings');
  if (warnings.length) {
    warnEl.innerHTML = warnings.join('<br>');
    warnEl.style.display = '';
  } else {
    warnEl.style.display = 'none';
  }
}

// ── Copy & Download ──
function copyToClipboard(id) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(() => {
    // brief visual feedback
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✅ Copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function downloadFile(filename, id) {
  const text = document.getElementById(id).textContent;
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}