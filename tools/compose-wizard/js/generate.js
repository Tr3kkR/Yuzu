/* ── Compose File Generator ── */

async function generate() {
  const pgMode = val('pg-mode');
  const pgSuperPass = val('pg-superuser-pass');
  const pgAppPass = val('pg-app-pass');
  const pgDsn = val('pg-dsn');

  // Guard the load-bearing substrate invariants before emitting anything —
  // a compose/.env pair that the postgres image will refuse to boot is worse
  // than no output.
  if (pgMode === 'bundled') {
    if (!pgSuperPass || !pgAppPass) {
      alert('Bundled PostgreSQL: set BOTH the superuser and app-role passwords on the Data step (use 🎲 Generate). The yuzu-postgres image refuses to boot without them.');
      return;
    }
    if (pgSuperPass === pgAppPass) {
      alert('Bundled PostgreSQL: the superuser and app-role passwords must be DISTINCT — the image\'s first-boot init refuses to run if they are equal.');
      return;
    }
  } else if (!pgDsn) {
    alert('External PostgreSQL: supply a DSN on the Data step, or switch to the bundled mode. The server needs a database to talk to.');
    return;
  }

  const tlsMode = val('tls-mode');
  const gateway = chk('include-gateway');

  if (tlsMode === 'operator' && (!val('tls-cert') || !val('tls-key'))) {
    alert('Operator certs: set BOTH the certificate and key path on the Core step, or switch to Default certs (the server then auto-generates them).');
    return;
  }

  // #1485: the secure gateway↔server upstream (mutual TLS + shared cert volume +
  // --cert-group) is only emitted for default-certs, where the server mints the
  // gateway leaf the wizard can wire. With operator certs we don't know the
  // gateway-leaf layout, so rather than generate a gateway that can't reach the
  // server, block and point at the worked reference. Plaintext+gateway stays
  // plaintext (it works — the server isn't mTLS).
  if (gateway && tlsMode === 'operator') {
    alert('Gateway + operator certs is not wired by the wizard yet: the gateway needs its own client leaf from your CA to reach the server\'s mutual-TLS upstream. Use Default certs (auto-generated, fully wired) or Plaintext for the gateway, or follow deploy/docker/docker-compose.reference-gateway.yml.');
    return;
  }

  // #1488: the admin credential row is PBKDF2-HMAC-SHA256 (100k iters), derived
  // in-browser via SubtleCrypto. Requires a secure context (https / localhost /
  // file://) — fail loudly rather than emit a stale, non-validating hash.
  if (!window.crypto || !crypto.subtle) {
    alert('Cannot hash the admin password: this browser exposes no Web Crypto Subtle API. Serve the wizard over http://localhost (e.g. `python3 -m http.server`) or open it via file:// in a modern browser, then retry.');
    return;
  }
  const authLine = await computeAuthLine(val('admin-user'), 'admin', val('admin-pass'));

  // #1483: a fresh Erlang distribution cookie so the gateway doesn't fail-closed
  // on the insecure default. Lands only in .env.
  const gwCookie = randHex(32);

  const config = {
    authLine: authLine,
    gwCookie: gwCookie,
    version: val('yuzu-version'),
    adminUser: val('admin-user'),
    adminPass: val('admin-pass'),
    dashboardPort: num('dashboard-port'),
    grpcPort: num('grpc-port'),
    mgmtPort: num('mgmt-port'),
    gwUpstreamPort: num('gateway-upstream-port'),
    tlsMode: tlsMode,
    tlsCert: val('tls-cert'),
    tlsKey: val('tls-key'),
    tlsCaCert: val('tls-ca-cert'),
    certSans: val('cert-san'),
    persistCerts: chk('persist-certs'),
    dataDir: val('data-dir'),
    pgMode: pgMode,
    pgBundled: pgMode === 'bundled',
    pgSuperPass: pgSuperPass,
    pgAppPass: pgAppPass,
    pgDsn: pgDsn,
    clickhouse: chk('include-clickhouse'),
    chHttpPort: num('ch-http-port'),
    chNativePort: num('ch-native-port'),
    chUser: val('ch-user'),
    chPass: val('ch-pass'),
    chDb: val('ch-db'),
    persistentVolumes: chk('persistent-volumes'),
    prometheus: chk('include-prometheus'),
    promPort: num('prom-port'),
    grafana: chk('include-grafana'),
    grafanaPort: num('grafana-port'),
    grafanaPass: val('grafana-pass'),
    gateway: chk('include-gateway'),
    gwAgentPort: num('gw-agent-port'),
    gwMgmtPort: num('gw-mgmt-port'),
    gwHealthPort: num('gw-health-port'),
    gwMetricsPort: num('gw-metrics-port'),
    gwPoolSize: num('gw-pool-size'),
    gwTls: chk('gw-tls'),
  };

  const compose = generateCompose(config);
  const env = generateEnv(config);

  document.getElementById('compose-output').textContent = compose;
  document.getElementById('env-output').textContent = env;
  document.getElementById('output').style.display = '';
  document.getElementById('output').scrollIntoView({ behavior: 'smooth' });
}

// Hex-encode `n` cryptographically-random bytes.
function randHex(n) {
  return Array.from(crypto.getRandomValues(new Uint8Array(n)),
                    b => b.toString(16).padStart(2, '0')).join('');
}

// #1488: produce a server auth-config row `username:role:salt_hex:hash_hex`
// matching the server's KDF exactly — PBKDF2-HMAC-SHA256, 100000 iterations,
// 32-byte derived key, random 16-byte salt (auth.cpp pbkdf2_sha256 /
// kPbkdf2Iterations). The previous hardcoded row put the *password* in the role
// field and shipped a hash for no current KDF, so `admin/admin` 401'd.
async function computeAuthLine(user, role, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const hex = buf => Array.from(new Uint8Array(buf),
                                b => b.toString(16).padStart(2, '0')).join('');
  return `${user}:${role}:${hex(salt)}:${hex(bits)}`;
}

function generateEnv(c) {
  return `# ── Yuzu Environment Variables ──
# Generated by Yuzu Compose Wizard
# Edit this file to reconfigure without touching docker-compose.yml

# Yuzu version (container image tag)
YUZU_VERSION=${c.version}

# ── Server ──
YUZU_DASHBOARD_PORT=${c.dashboardPort}
YUZU_GRPC_PORT=${c.grpcPort}
YUZU_MGMT_PORT=${c.mgmtPort}
YUZU_GATEWAY_UPSTREAM_PORT=${c.gwUpstreamPort}
YUZU_ADMIN_USER=${c.adminUser}
${c.pgBundled ? `
# ── PostgreSQL (server storage substrate, ADR-0006/0008) ──
# Two DISTINCT credentials — keep both in a secrets manager, not in git.
# The superuser password stays inside the postgres container; the app-role
# password is what the server's DSN carries. They MUST differ (the image's
# first-boot init refuses to run if they are equal). Rotate with:
#   openssl rand -hex 24
YUZU_POSTGRES_PASSWORD=${c.pgSuperPass}
YUZU_DB_PASSWORD=${c.pgAppPass}` : `
# ── PostgreSQL (external / managed substrate) ──
# Full server DSN — carries the app-role password, never a superuser
# credential. Keep it out of git; this file is the only place it lives.
YUZU_POSTGRES_DSN=${c.pgDsn}`}
${c.clickhouse ? `YUZU_CLICKHOUSE_PASSWORD=${c.chPass}
YUZU_CLICKHOUSE_DB=${c.chDb}
YUZU_CLICKHOUSE_USER=${c.chUser}` : ''}
${c.prometheus ? `
# ── Prometheus ──
YUZU_PROMETHEUS_PORT=${c.promPort}` : ''}
${c.grafana ? `
# ── Grafana ──
YUZU_GRAFANA_PORT=${c.grafanaPort}
YUZU_GRAFANA_ADMIN_PASSWORD=${c.grafanaPass}` : ''}
${c.gateway ? `
# ── Gateway ──
YUZU_GW_AGENT_PORT=${c.gwAgentPort}
YUZU_GW_MGMT_PORT=${c.gwMgmtPort}
YUZU_GW_HEALTH_PORT=${c.gwHealthPort}
YUZU_GW_METRICS_PORT=${c.gwMetricsPort}
# Erlang distribution cookie — the gateway fail-closes on the insecure default.
# Generated unique per stack; keep it out of git. Rotate with: openssl rand -hex 32
# (Single ephemeral node? You may instead set YUZU_GW_ALLOW_DEFAULT_COOKIE=1.)
YUZU_GW_COOKIE=${c.gwCookie}` : ''}`;
}

// Build the effective --cert-san set for the auto-generated default certs:
// the operator's comma-separated entries plus dns:gateway when the gateway is
// enabled (agents dial the gateway by that service name, so its leaf must carry
// the SAN or hostname validation fails — PKI PR5b gateway-edge requirement).
function effectiveCertSans(c) {
  const sans = [];
  if (c.gateway) sans.push('dns:gateway');
  // Secure gateway upstream: the gateway dials the `server` service by name over
  // mutual TLS, so the server leaf must carry dns:server for SNI verification.
  if (c.gateway && c.tlsMode === 'default') sans.push('dns:server');
  for (const raw of (c.certSans || '').split(',')) {
    const s = raw.trim();
    if (s && !sans.includes(s)) sans.push(s);
  }
  return sans;
}

function generateCompose(c) {
  // HTTPS is served unless plaintext mode explicitly disables it. In TLS modes
  // the dashboard/API is HTTPS on container port 8443 (8080 is an HTTP→HTTPS
  // redirect); plaintext serves HTTP on 8080 (#1484).
  const tls = c.tlsMode !== 'plaintext';
  const webScheme = tls ? 'https' : 'http';
  const webContainerPort = tls ? 8443 : 8080;
  // #1485: full secure gateway topology (mutual-TLS upstream + shared certs) is
  // emitted only for default-certs + gateway.
  const secureGateway = c.gateway && c.tlsMode === 'default';
  // A NAMED cert volume is required to share /etc/yuzu/certs with the gateway
  // (anonymous volumes can't be shared), and also when the operator opted to
  // persist certs with named volumes. secureGateway forces it regardless.
  const certVolNamed = c.tlsMode === 'default'
    && (secureGateway || (c.persistCerts && c.persistentVolumes));

  let y = `## Yuzu Stack — Generated by Yuzu Compose Wizard
##
## Customised for your deployment. Edit .env for quick reconfiguration.
##
## Usage:
##   docker compose up -d
##   docker compose logs -f
##   docker compose down -v    # ⚠️ -v removes data volumes!
##
## Dashboard:   ${webScheme}://localhost:${c.dashboardPort}  (${c.adminUser} / <your-password>)
${c.grafana ? `## Grafana:     http://localhost:${c.grafanaPort}  (admin / ${c.grafanaPass})` : ''}
${c.prometheus ? `## Prometheus:  http://localhost:${c.promPort}` : ''}
${c.clickhouse ? `## ClickHouse:  http://localhost:${c.chHttpPort}  (${c.chUser} / ${c.chPass})` : ''}
##
## Connect an agent:
${c.tlsMode === 'plaintext'
  ? `##   yuzu-agent --server localhost:${c.gateway ? c.gwAgentPort : c.grpcPort} --no-tls`
  : `##   # TLS is on. Give the agent the server's CA so it can verify the cert:
##   #   curl -sk ${webScheme}://localhost:${c.dashboardPort}/api/v1/ca/root -o ca.pem
##   yuzu-agent --server localhost:${c.gateway ? c.gwAgentPort : c.grpcPort} --ca-cert ca.pem`}
##   (approve the agent in Settings, then restart the agent)
##

`;

  // ── Configs ──
  y += `configs:\n`;
  y += `  # ── Server RBAC config ──\n`;
  y += `  # NOTE: RBAC is enabled but may not enforce in all Yuzu versions.\n`;
  y += `  # See: https://github.com/Tr3kkR/Yuzu/issues/388\n`;
  y += `  server-cfg:\n`;
  y += `    content: |\n`;
  y += `      # ${c.adminUser} / <the password you entered> — PBKDF2-HMAC-SHA256, 100k iters.\n`;
  y += `      # Regenerate with: yuzu-server hash-password ${c.adminUser} <password>\n`;
  y += `      ${c.authLine}\n`;
  y += `      \n`;
  y += `      [rbac]\n`;
  y += `      enabled = true\n`;

  if (c.gateway) {
    y += `\n  # ── Gateway (Erlang/OTP) sys.config ──\n`;
    y += `  gateway-sys-config:\n`;
    y += `    content: |\n`;
    y += `      [\n`;
    y += `          {yuzu_gw, [\n`;
    y += `              {agent_listen_addr, "0.0.0.0"},\n`;
    y += `              {agent_listen_port, 50051},\n`;
    y += `              {mgmt_listen_addr, "0.0.0.0"},\n`;
    y += `              {mgmt_listen_port, 50063},\n`;
    y += `              {upstream_addr, "server"},\n`;
    y += `              {upstream_port, ${c.gwUpstreamPort}},\n`;
    y += `              {upstream_pool_size, ${c.gwPoolSize}},\n`;
    y += `              {heartbeat_batch_interval_ms, 1000},\n`;
    y += `              {default_command_timeout_s, 300},\n`;
    y += `              {prometheus_port, 9568},\n`;
    y += `              {health_port, 8081},\n`;
    y += `              {telemetry_gauge_interval_ms, 10000},\n`;
    y += `              {circuit_breaker_failure_threshold, 5},\n`;
    y += `              {circuit_breaker_reset_timeout_ms, 10000},\n`;
    y += `              {circuit_breaker_max_reset_timeout_ms, 300000},\n`;
    y += `              {backpressure_threshold, 1000},\n`;
    y += `              {hash_ring_vnodes, 256}\n`;
    y += `          ]},\n`;
    if (secureGateway) {
      // #1485: grpcbox reads its OWN TLS config (the YUZU_GW_TLS_* env is
      // advisory only, #1291). Mirrors deploy/docker/reference-gateway-sys.config:
      //  - upstream to `server` is MUTUAL TLS (the server's gateway-upstream
      //    listener requires a client cert when default certs are active);
      //  - the agent listener (:50051) is ONE-WAY TLS so an unenrolled agent can
      //    still bootstrap (no client cert yet) over an encrypted hop;
      //  - the mgmt listener (:50063) is STRICT mTLS (the patched grpcbox
      //    defaults verify_peer + fail_if_no_peer_cert when omitted).
      // Cert paths are the server-generated defaults in the shared cert volume,
      // readable by the gateway via the --cert-group yuzu-pki group share.
      y += `          {grpcbox, [\n`;
      y += `              {client, #{channels => [\n`;
      y += `                  {default_channel, [{https, "server", ${c.gwUpstreamPort}, [\n`;
      y += `                      {cacertfile, "/etc/yuzu/certs/default-ca.pem"},\n`;
      y += `                      {certfile,   "/etc/yuzu/certs/default-gateway.pem"},\n`;
      y += `                      {keyfile,    "/etc/yuzu/certs/default-gateway.key"},\n`;
      y += `                      {verify, verify_peer},\n`;
      y += `                      {depth, 2},\n`;
      y += `                      {versions, ['tlsv1.2']},\n`;
      y += `                      {ciphers, ["ECDHE-ECDSA-AES256-GCM-SHA384",\n`;
      y += `                                 "ECDHE-ECDSA-AES128-GCM-SHA256",\n`;
      y += `                                 "ECDHE-ECDSA-CHACHA20-POLY1305"]}\n`;
      y += `                  ]}], #{}}\n`;
      y += `              ]}},\n`;
      y += `              {servers, [\n`;
      y += `                  #{grpc_opts => #{\n`;
      y += `                      service_protos => [agent_pb],\n`;
      y += `                      services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service}\n`;
      y += `                  },\n`;
      y += `                  listen_opts => #{port => 50051, ip => {0,0,0,0}},\n`;
      y += `                  transport_opts => #{ssl => true,\n`;
      y += `                                      certfile   => "/etc/yuzu/certs/default-gateway.pem",\n`;
      y += `                                      keyfile    => "/etc/yuzu/certs/default-gateway.key",\n`;
      y += `                                      cacertfile => "/etc/yuzu/certs/default-ca.pem",\n`;
      y += `                                      verify => verify_none,\n`;
      y += `                                      fail_if_no_peer_cert => false}},\n`;
      y += `                  #{grpc_opts => #{\n`;
      y += `                      service_protos => [management_pb],\n`;
      y += `                      services => #{'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service}\n`;
      y += `                  },\n`;
      y += `                  listen_opts => #{port => 50063, ip => {0,0,0,0}},\n`;
      y += `                  transport_opts => #{ssl => true,\n`;
      y += `                                      certfile   => "/etc/yuzu/certs/default-gateway.pem",\n`;
      y += `                                      keyfile    => "/etc/yuzu/certs/default-gateway.key",\n`;
      y += `                                      cacertfile => "/etc/yuzu/certs/default-ca.pem"}}\n`;
      y += `              ]}\n`;
      y += `          ]},\n`;
    } else {
      // Plaintext gateway (plaintext TLS mode): the server's upstream is not mTLS,
      // so the gateway dials it over plain HTTP/2 and the listeners are plaintext.
      // ⚠️ Do NOT internet-expose :50051 in this mode (command fan-out = fleet RCE).
      y += `          {grpcbox, [\n`;
      y += `              {client, #{channels => [\n`;
      y += `                  {default_channel, [{http, "server", ${c.gwUpstreamPort}, []}], #{}}\n`;
      y += `              ]}},\n`;
      y += `              {servers, [\n`;
      y += `                  #{grpc_opts => #{\n`;
      y += `                      service_protos => [agent_pb],\n`;
      y += `                      services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service}\n`;
      y += `                  },\n`;
      y += `                  listen_opts => #{port => 50051, ip => {0,0,0,0}}},\n`;
      y += `                  #{grpc_opts => #{\n`;
      y += `                      service_protos => [management_pb],\n`;
      y += `                      services => #{'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service}\n`;
      y += `                  },\n`;
      y += `                  listen_opts => #{port => 50063, ip => {0,0,0,0}}}\n`;
      y += `              ]}\n`;
      y += `          ]},\n`;
    }
    y += `          {kernel, [\n`;
    y += `              {connect_all, false},\n`;
    y += `              {net_ticktime, 30},\n`;
    y += `              {logger_level, info},\n`;
    y += `              {logger, [\n`;
    y += `                  {handler, default, logger_std_h, #{\n`;
    y += `                      level => info,\n`;
    y += `                      formatter => {logger_formatter, #{\n`;
    y += `                          template => [time, " [", level, "] ", pid, " ", msg, "\\n"]\n`;
    y += `                      }}\n`;
    y += `                  }}\n`;
    y += `              ]}\n`;
    y += `          ]}\n`;
    y += `      ].\n`;
  }

  if (c.prometheus) {
    y += `\n  # ── Prometheus config ──\n`;
    y += `  prometheus-config:\n`;
    y += `    content: |\n`;
    y += `      global:\n`;
    y += `        scrape_interval: 15s\n`;
    y += `        evaluation_interval: 15s\n`;
    y += `      scrape_configs:\n`;
    y += `        - job_name: 'yuzu-server'\n`;
    y += `          metrics_path: '/metrics'\n`;
    if (tls) {
      // TLS modes: the server serves /metrics over HTTPS on 8443 (8080 just
      // redirects). Scrape https and skip verification (internal default CA).
      y += `          scheme: https\n`;
      y += `          tls_config:\n`;
      y += `            insecure_skip_verify: true\n`;
    }
    y += `          static_configs:\n`;
    y += `            - targets: ['server:${webContainerPort}']\n`;
    y += `              labels:\n`;
    y += `                component: 'server'\n`;
    if (c.gateway) {
      y += `        - job_name: 'yuzu-gateway'\n`;
      y += `          metrics_path: '/metrics'\n`;
      y += `          static_configs:\n`;
      y += `            - targets: ['gateway:9568']\n`;
      y += `              labels:\n`;
      y += `                component: 'gateway'\n`;
    }
  }

  if (c.grafana) {
    y += `\n  # ── Grafana provisioning ──\n`;
    y += `  grafana-datasource:\n`;
    y += `    content: |\n`;
    y += `      apiVersion: 1\n`;
    y += `      datasources:\n`;
    y += `        - name: Prometheus\n`;
    y += `          type: prometheus\n`;
    y += `          access: proxy\n`;
    y += `          url: http://prometheus:9090\n`;
    y += `          isDefault: true\n`;
    y += `          editable: false\n`;
    y += `  grafana-dashboard-provider:\n`;
    y += `    content: |\n`;
    y += `      apiVersion: 1\n`;
    y += `      providers:\n`;
    y += `        - name: Yuzu\n`;
    y += `          orgId: 1\n`;
    y += `          folder: Yuzu\n`;
    y += `          type: file\n`;
    y += `          disableDeletion: false\n`;
    y += `          editable: true\n`;
    y += `          options:\n`;
    y += `            path: /var/lib/grafana/dashboards\n`;
    y += `            foldersFromFilesStructure: false\n`;
    y += `  # Dashboard JSON files — requires deploy/grafana/ in your Yuzu checkout\n`;
    y += `  grafana-dashboard-main:\n`;
    y += `    file: deploy/grafana/yuzu-dashboard.json\n`;
    y += `  grafana-dashboard-fleet:\n`;
    y += `    file: deploy/grafana/yuzu-fleet-dashboard.json\n`;
    y += `  grafana-dashboard-gateway:\n`;
    y += `    file: deploy/grafana/yuzu-gateway-dashboard.json\n`;
    y += `  grafana-dashboard-analytics:\n`;
    y += `    file: deploy/grafana/yuzu-analytics-dashboard.json\n`;
  }

  if (c.clickhouse) {
    y += `\n  # ── ClickHouse init SQL ──\n`;
    y += `  clickhouse-init:\n`;
    y += `    content: |\n`;
    y += `      CREATE DATABASE IF NOT EXISTS ${c.chDb};\n`;
    y += `      CREATE TABLE IF NOT EXISTS ${c.chDb}.yuzu_events (\n`;
    y += `          tenant_id       LowCardinality(String)  DEFAULT 'default',\n`;
    y += `          agent_id        String                  DEFAULT '',\n`;
    y += `          session_id      String                  DEFAULT '',\n`;
    y += `          event_type      LowCardinality(String),\n`;
    y += `          event_time      DateTime64(3, 'UTC'),\n`;
    y += `          ingest_time     DateTime64(3, 'UTC')    DEFAULT now64(3),\n`;
    y += `          plugin          LowCardinality(String)  DEFAULT '',\n`;
    y += `          capability      LowCardinality(String)  DEFAULT '',\n`;
    y += `          correlation_id  String                  DEFAULT '',\n`;
    y += `          severity        Enum8('debug'=0,'info'=1,'warn'=2,'error'=3,'critical'=4) DEFAULT 'info',\n`;
    y += `          source          LowCardinality(String)  DEFAULT 'server',\n`;
    y += `          hostname        String                  DEFAULT '',\n`;
    y += `          os              LowCardinality(String)  DEFAULT '',\n`;
    y += `          arch            LowCardinality(String)  DEFAULT '',\n`;
    y += `          agent_version   LowCardinality(String)  DEFAULT '',\n`;
    y += `          principal       String                  DEFAULT '',\n`;
    y += `          principal_role  LowCardinality(String)  DEFAULT '',\n`;
    y += `          attributes      String                  DEFAULT '{}',\n`;
    y += `          payload         String                  DEFAULT '{}',\n`;
    y += `          schema_version  UInt8                   DEFAULT 1\n`;
    y += `      ) ENGINE = MergeTree()\n`;
    y += `        PARTITION BY toYYYYMM(event_time)\n`;
    y += `        ORDER BY (tenant_id, event_type, event_time, agent_id)\n`;
    y += `        TTL toDate(event_time) + INTERVAL 365 DAY;\n`;
    y += `      ALTER TABLE ${c.chDb}.yuzu_events ADD INDEX IF NOT EXISTS idx_agent_id agent_id TYPE bloom_filter GRANULARITY 4;\n`;
    y += `      ALTER TABLE ${c.chDb}.yuzu_events ADD INDEX IF NOT EXISTS idx_correlation_id correlation_id TYPE bloom_filter GRANULARITY 4;\n`;
    y += `      ALTER TABLE ${c.chDb}.yuzu_events ADD INDEX IF NOT EXISTS idx_hostname hostname TYPE bloom_filter GRANULARITY 4;\n`;
    y += `      CREATE MATERIALIZED VIEW IF NOT EXISTS ${c.chDb}.mv_command_duration_hourly\n`;
    y += `      ENGINE = AggregatingMergeTree()\n`;
    y += `      PARTITION BY toYYYYMM(hour)\n`;
    y += `      ORDER BY (tenant_id, plugin, hour)\n`;
    y += `      AS SELECT\n`;
    y += `          tenant_id, plugin,\n`;
    y += `          toStartOfHour(event_time) AS hour,\n`;
    y += `          quantileState(0.5)(JSONExtractFloat(payload, 'duration_ms'))  AS p50,\n`;
    y += `          quantileState(0.95)(JSONExtractFloat(payload, 'duration_ms')) AS p95,\n`;
    y += `          quantileState(0.99)(JSONExtractFloat(payload, 'duration_ms')) AS p99,\n`;
    y += `          countState() AS total\n`;
    y += `      FROM ${c.chDb}.yuzu_events\n`;
    y += `      WHERE event_type = 'command.completed'\n`;
    y += `      GROUP BY tenant_id, plugin, hour;\n`;
    y += `      CREATE MATERIALIZED VIEW IF NOT EXISTS ${c.chDb}.mv_agent_activity_daily\n`;
    y += `      ENGINE = SummingMergeTree()\n`;
    y += `      PARTITION BY toYYYYMM(day)\n`;
    y += `      ORDER BY (tenant_id, agent_id, day, event_type)\n`;
    y += `      AS SELECT\n`;
    y += `          tenant_id, agent_id,\n`;
    y += `          toDate(event_time) AS day,\n`;
    y += `          event_type,\n`;
    y += `          count() AS event_count\n`;
    y += `      FROM ${c.chDb}.yuzu_events\n`;
    y += `      GROUP BY tenant_id, agent_id, day, event_type;\n`;
  }

  // ── Services ──
  y += `\nservices:\n`;

  // Yuzu Server
  y += `  # ── Yuzu Server ──────────────────────────────────────────────────────\n`;
  y += `  server:\n`;
  y += `    image: ghcr.io/tr3kkr/yuzu-server:\${YUZU_VERSION:-${c.version}}\n`;
  y += `    container_name: yuzu-server\n`;
  y += `    restart: unless-stopped\n`;
  y += `    ports:\n`;
  y += `      - "${c.dashboardPort}:${webContainerPort}"     # Web dashboard + REST API (${webScheme.toUpperCase()})\n`;
  y += `      - "${c.grpcPort}:50051"   # Agent gRPC (direct-connect agents)\n`;
  y += `      - "${c.mgmtPort}:50052"   # Management gRPC\n`;
  y += `      - "${c.gwUpstreamPort}:${c.gwUpstreamPort}"   # Gateway upstream\n`;
  y += `    environment:\n`;
  y += `      - YUZU_LOG_LEVEL=info\n`;
  y += `      - YUZU_LOG_FORMAT=json\n`;
  // Postgres substrate DSN (ADR-0006/0008). Consumed via env var, NOT a CLI
  // flag — the server reads YUZU_POSTGRES_DSN from the environment. The DSN
  // carries the APP role password (interpolated from .env), never the
  // superuser's, so a leaked server environment can't disclose superuser creds.
  if (c.pgBundled) {
    y += `      # Postgres substrate DSN (ADR-0006/0008). App-role password comes\n`;
    y += `      # from .env (YUZU_DB_PASSWORD) — never baked into this file.\n`;
    y += `      - YUZU_POSTGRES_DSN=postgresql://yuzu:\${YUZU_DB_PASSWORD}@postgres:5432/yuzu\n`;
  } else {
    y += `      # External/managed Postgres — full DSN supplied via .env.\n`;
    y += `      - YUZU_POSTGRES_DSN=\${YUZU_POSTGRES_DSN}\n`;
  }
  y += `    command:\n`;
  y += `      - "--listen"\n`;
  y += `      - "0.0.0.0:50051"\n`;
  if (c.tlsMode === 'plaintext') {
    // Insecure dev mode — overrides secure-by-default. Do NOT expose :50051.
    y += `      - "--no-tls"\n`;
    y += `      - "--no-https"\n`;
  } else if (c.tlsMode === 'operator') {
    // Operator-supplied PEM material, bind-mounted read-only below.
    y += `      - "--cert"\n`;
    y += `      - "${c.tlsCert}"\n`;
    y += `      - "--key"\n`;
    y += `      - "${c.tlsKey}"\n`;
    if (c.tlsCaCert) {
      y += `      - "--ca-cert"\n`;
      y += `      - "${c.tlsCaCert}"\n`;
    }
  } else {
    // Default mode: emit NO --cert/--key/--no-tls. The server auto-generates a
    // per-install CA + leaf certs on first boot (encrypted-by-default). Extra
    // SANs make those leaves validate for the names agents actually dial.
    const sans = effectiveCertSans(c);
    if (sans.length) {
      y += `      # Auto-generated default certs get these extra SANs so agents can\n`;
      y += `      # validate the gateway/server hostname (see PKI default-certs).\n`;
      for (const s of sans) {
        y += `      - "--cert-san"\n`;
        y += `      - "${s}"\n`;
      }
    }
    if (secureGateway) {
      // #1485: chgrp the shared cert dir (0750) + gateway leaf key (0640) to the
      // fixed gid-2000 yuzu-pki group baked into all images, so the gateway (a
      // different uid) can read default-gateway.key. Server/CA/HTTPS keys stay 0600.
      y += `      - "--cert-group"\n`;
      y += `      - "yuzu-pki"\n`;
    }
  }
  y += `      - "--web-address"\n`;
  y += `      - "0.0.0.0"\n`;
  if (tls) {
    // TLS modes: dashboard/API is HTTPS on 8443 (8080 stays an auto HTTP→HTTPS
    // redirect). #1484.
    y += `      - "--https-port"\n`;
    y += `      - "8443"\n`;
  } else {
    y += `      - "--web-port"\n`;
    y += `      - "8080"\n`;
  }
  y += `      - "--config"\n`;
  y += `      - "/etc/yuzu/yuzu-server.cfg"\n`;
  y += `      - "--data-dir"\n`;
  y += `      - "${c.dataDir}"\n`;
  y += `      # ⚠️ --data-dir is REQUIRED. Without it, SQLite stores fail silently.\n`;
  if (c.gateway) {
    y += `      - "--gateway-upstream"\n`;
    y += `      - "0.0.0.0:${c.gwUpstreamPort}"\n`;
    y += `      - "--gateway-mode"\n`;
    y += `      - "--gateway-command-addr"\n`;
    y += `      - "gateway:50063"\n`;
  }
  y += `      - "--metrics-no-auth"\n`;
  if (c.clickhouse) {
    y += `      - "--clickhouse-url"\n`;
    y += `      - "http://clickhouse:8123"\n`;
    y += `      - "--clickhouse-database"\n`;
    y += `      - "${c.chDb}"\n`;
    y += `      - "--clickhouse-table"\n`;
    y += `      - "yuzu_events"\n`;
    y += `      - "--clickhouse-user"\n`;
    y += `      - "${c.chUser}"\n`;
    y += `      - "--clickhouse-password"\n`;
    y += `      - "${c.chPass}"\n`;
  }
  y += `    configs:\n`;
  y += `      - source: server-cfg\n`;
  y += `        target: /etc/yuzu/yuzu-server.cfg\n`;
  y += `    volumes:\n`;
  if (c.persistentVolumes) {
    y += `      - server-data:${c.dataDir}\n`;
  } else {
    y += `      - ${c.dataDir}\n`;
  }
  // Cert directory (/etc/yuzu/certs = auth::default_cert_dir()). In default mode
  // the auto-generated CA lives here and MUST persist across recreates, or every
  // `down && up` mints a new CA and breaks enrolled-agent trust. In operator mode
  // bind-mount the host PEM material read-only.
  if (c.tlsMode === 'default') {
    if (certVolNamed) {
      // Named volume: persists the CA across recreates AND (for secureGateway) is
      // shared read-only into the gateway so it can read default-gateway.key.
      y += `      - server-certs:/etc/yuzu/certs\n`;
    } else if (c.persistCerts) {
      y += `      - /etc/yuzu/certs\n`;
    }
    // else: persist off, no gateway → certs live in the container layer (ephemeral).
  } else if (c.tlsMode === 'operator') {
    y += `      # Put server.pem / server.key (and ca.pem for mTLS) in ./certs.\n`;
    y += `      - ./certs:/etc/yuzu/certs:ro\n`;
  }
  y += `    healthcheck:\n`;
  // #1487: the server image ships bash but NOT curl, so probe the listening port
  // with a bash /dev/tcp TCP connect (matches docker-compose.uat.yml). Targets the
  // real serving port: 8443 in TLS modes, 8080 in plaintext (#1484). A TCP-connect
  // check avoids speaking HTTP to the wrong scheme.
  y += `      test: ["CMD", "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${webContainerPort}"]\n`;
  y += `      interval: 10s\n`;
  y += `      timeout: 3s\n`;
  y += `      retries: 30\n`;
  y += `      start_period: 10s\n`;
  // Gate server start on Postgres (bundled mode) and ClickHouse readiness so
  // migrations don't race an unready substrate.
  if (c.pgBundled || c.clickhouse) {
    y += `    depends_on:\n`;
    if (c.pgBundled) {
      y += `      postgres:\n`;
      y += `        condition: service_healthy\n`;
    }
    if (c.clickhouse) {
      y += `      clickhouse:\n`;
      y += `        condition: service_healthy\n`;
    }
  }

  // PostgreSQL (server storage substrate) — bundled mode only. In external
  // mode the server's YUZU_POSTGRES_DSN points at a managed instance and no
  // local container is generated.
  if (c.pgBundled) {
    y += `\n  # ── PostgreSQL (server storage substrate, ADR-0006/0008) ─────────────\n`;
    y += `  # Release-pinned yuzu-postgres image: PostgreSQL 16 + pgvector + a\n`;
    y += `  # first-boot init that creates the app role/database. Per-store schemas\n`;
    y += `  # are created at runtime by the server's migration runner. Using an\n`;
    y += `  # external/managed Postgres instead is first-class — re-run the wizard\n`;
    y += `  # and pick "External / managed".\n`;
    y += `  postgres:\n`;
    y += `    image: ghcr.io/tr3kkr/yuzu-postgres:\${YUZU_VERSION:-${c.version}}\n`;
    y += `    container_name: yuzu-postgres\n`;
    y += `    restart: unless-stopped\n`;
    y += `    environment:\n`;
    y += `      # Both passwords come from .env — the actual secrets never appear\n`;
    y += `      # in this compose file. They MUST be distinct (first-boot init\n`;
    y += `      # refuses to run otherwise); the superuser password stays inside\n`;
    y += `      # this container and is never carried by the server DSN.\n`;
    y += `      - POSTGRES_PASSWORD=\${YUZU_POSTGRES_PASSWORD}\n`;
    y += `      - YUZU_DB_PASSWORD=\${YUZU_DB_PASSWORD}\n`;
    y += `    volumes:\n`;
    if (c.persistentVolumes) {
      y += `      - postgres-data:/var/lib/postgresql/data\n`;
    } else {
      y += `      - /var/lib/postgresql/data\n`;
    }
    y += `    healthcheck:\n`;
    // -h 127.0.0.1 forces a TCP probe (initdb's temporary server is socket-only
    // mid-init); the psql leg dials the container hostname (not loopback, which
    // initdb leaves on 'trust') so it actually verifies the app credential.
    // $$ defers expansion to the container shell so the password never appears
    // in `docker compose config` output.
    y += `      test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U yuzu -d yuzu && psql \\"postgresql://yuzu:$\${YUZU_DB_PASSWORD}@$$(hostname):5432/yuzu\\" -tA -c 'SELECT 1' >/dev/null"]\n`;
    y += `      interval: 5s\n`;
    y += `      timeout: 5s\n`;
    y += `      retries: 12\n`;
    y += `      start_period: 10s\n`;
  }

  // Gateway
  if (c.gateway) {
    y += `\n  # ── Yuzu Gateway (Erlang/OTP) ────────────────────────────────────────\n`;
    y += `  gateway:\n`;
    y += `    image: ghcr.io/tr3kkr/yuzu-gateway:\${YUZU_VERSION:-${c.version}}\n`;
    y += `    container_name: yuzu-gateway\n`;
    y += `    restart: unless-stopped\n`;
    y += `    ports:\n`;
    y += `      - "${c.gwAgentPort}:50051"   # Agent-facing gRPC (mapped to avoid conflict with server)\n`;
    y += `      - "${c.gwMgmtPort}:50063"   # Management/command forwarding\n`;
    y += `      - "${c.gwHealthPort}:8081"     # Health/readiness\n`;
    y += `      - "${c.gwMetricsPort}:9568"     # Prometheus metrics\n`;
    y += `    environment:\n`;
    // #1483: a real distribution cookie from .env (the gateway fail-closes on the
    // insecure default). YUZU_GW_TLS_ENABLED is advisory only (#1291) — the actual
    // TLS posture lives in the grpcbox block of the mounted sys.config.
    y += `      - YUZU_GW_COOKIE=\${YUZU_GW_COOKIE}\n`;
    y += `      - YUZU_GW_TLS_ENABLED=${secureGateway || c.gwTls ? 'true' : 'false'}\n`;
    y += `    configs:\n`;
    y += `      - source: gateway-sys-config\n`;
    y += `        target: /opt/yuzu_gw/releases/0.2.0/sys.config\n`;
    if (secureGateway) {
      // #1485: read-only share of the server-generated CA + gateway leaf (the
      // server's --cert-group yuzu-pki made default-gateway.key group-readable).
      y += `    volumes:\n`;
      y += `      - server-certs:/etc/yuzu/certs:ro\n`;
    }
    // #1486: the gateway image ships no bash/curl, so the old `echo > /dev/tcp`
    // CMD-SHELL probe always failed (permanently "unhealthy"). The reference
    // compose omits a gateway healthcheck; gate startup on the server being healthy
    // instead so the gateway's upstream is reachable when it boots.
    y += `    depends_on:\n`;
    y += `      server:\n`;
    y += `        condition: service_healthy\n`;
  }

  // Prometheus
  if (c.prometheus) {
    y += `\n  # ── Prometheus ───────────────────────────────────────────────────────\n`;
    y += `  prometheus:\n`;
    y += `    image: prom/prometheus:latest\n`;
    y += `    container_name: yuzu-prometheus\n`;
    y += `    restart: unless-stopped\n`;
    y += `    ports:\n`;
    y += `      - "${c.promPort}:9090"\n`;
    y += `    configs:\n`;
    y += `      - source: prometheus-config\n`;
    y += `        target: /etc/prometheus/prometheus.yml\n`;
    y += `    volumes:\n`;
    y += `      - prometheus-data:/prometheus\n`;
    y += `    depends_on:\n`;
    y += `      - server\n`;
    if (c.gateway) y += `      - gateway\n`;
  }

  // Grafana
  if (c.grafana) {
    y += `\n  # ── Grafana ──────────────────────────────────────────────────────────\n`;
    y += `  grafana:\n`;
    y += `    image: grafana/grafana:latest\n`;
    y += `    container_name: yuzu-grafana\n`;
    y += `    restart: unless-stopped\n`;
    y += `    ports:\n`;
    y += `      - "${c.grafanaPort}:3000"\n`;
    y += `    environment:\n`;
    y += `      - GF_SECURITY_ADMIN_PASSWORD=${c.grafanaPass}\n`;
    y += `    configs:\n`;
    y += `      - source: grafana-datasource\n`;
    y += `        target: /etc/grafana/provisioning/datasources/prometheus.yml\n`;
    y += `      - source: grafana-dashboard-provider\n`;
    y += `        target: /etc/grafana/provisioning/dashboards/yuzu.yml\n`;
    y += `      - source: grafana-dashboard-main\n`;
    y += `        target: /var/lib/grafana/dashboards/yuzu-dashboard.json\n`;
    y += `      - source: grafana-dashboard-fleet\n`;
    y += `        target: /var/lib/grafana/dashboards/yuzu-fleet-dashboard.json\n`;
    y += `      - source: grafana-dashboard-gateway\n`;
    y += `        target: /var/lib/grafana/dashboards/yuzu-gateway-dashboard.json\n`;
    y += `      - source: grafana-dashboard-analytics\n`;
    y += `        target: /var/lib/grafana/dashboards/yuzu-analytics-dashboard.json\n`;
    y += `    volumes:\n`;
    y += `      - grafana-data:/var/lib/grafana\n`;
    y += `    depends_on:\n`;
    y += `      - prometheus\n`;
  }

  // ClickHouse
  if (c.clickhouse) {
    y += `\n  # ── ClickHouse ───────────────────────────────────────────────────────\n`;
    y += `  clickhouse:\n`;
    y += `    image: clickhouse/clickhouse-server:latest\n`;
    y += `    container_name: yuzu-clickhouse\n`;
    y += `    restart: unless-stopped\n`;
    y += `    ports:\n`;
    y += `      - "${c.chHttpPort}:8123"     # HTTP interface\n`;
    y += `      - "${c.chNativePort}:9000"     # Native protocol\n`;
    y += `    environment:\n`;
    y += `      - CLICKHOUSE_DB=${c.chDb}\n`;
    y += `      - CLICKHOUSE_USER=${c.chUser}\n`;
    y += `      - CLICKHOUSE_PASSWORD=${c.chPass}\n`;
    y += `    configs:\n`;
    y += `      - source: clickhouse-init\n`;
    y += `        target: /docker-entrypoint-initdb.d/init.sql\n`;
    y += `    volumes:\n`;
    y += `      - clickhouse-data:/var/lib/clickhouse\n`;
    y += `    ulimits:\n`;
    y += `      nofile:\n`;
    y += `        soft: 262144\n`;
    y += `        hard: 262144\n`;
    y += `    healthcheck:\n`;
    y += `      test: ["CMD", "clickhouse-client", "--password", "${c.chPass}", "-q", "SELECT 1"]\n`;
    y += `      interval: 10s\n`;
    y += `      timeout: 5s\n`;
    y += `      retries: 5\n`;
  }

  // Volumes — declared whenever any named volume is referenced. certVolNamed can
  // be true even with named volumes off (secureGateway forces a shareable cert
  // volume), so it's declared independently or compose errors on an undefined volume.
  if (c.persistentVolumes || certVolNamed) {
    y += `\nvolumes:\n`;
    if (c.persistentVolumes) y += `  server-data:\n`;
    if (certVolNamed) y += `  server-certs:\n`;
    if (c.persistentVolumes && c.pgBundled) y += `  postgres-data:\n`;
    if (c.persistentVolumes && c.prometheus) y += `  prometheus-data:\n`;
    if (c.persistentVolumes && c.grafana) y += `  grafana-data:\n`;
    if (c.persistentVolumes && c.clickhouse) y += `  clickhouse-data:\n`;
  }

  return y;
}