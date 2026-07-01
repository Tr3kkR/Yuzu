# Platform-specific crypto for auth module
# Windows: bcrypt.lib + winhttp.lib linked via #pragma comment(lib) in source
if host_machine.system() == 'windows'
  auth_crypto_deps = []
else
  openssl_dep = dependency('openssl', required: true, include_type: 'system')
  auth_crypto_deps = [openssl_dep]
endif

# OpenSSL for HTTPS (cpp-httplib SSLServer support)
# On Linux/macOS, openssl_dep is already declared above.
# On Windows, OpenSSL is available transitively via gRPC/vcpkg.
if host_machine.system() == 'windows'
  openssl_dep = dependency('openssl', method: 'cmake', modules: ['OpenSSL::SSL', 'OpenSSL::Crypto'], required: false, include_type: 'system')
  if not openssl_dep.found()
    # Fallback: try pkg-config or find_library
    _ssl_lib = cxx.find_library('libssl', required: false)
    _crypto_lib = cxx.find_library('libcrypto', required: false)
    if _ssl_lib.found() and _crypto_lib.found()
      openssl_dep = declare_dependency(dependencies: [_ssl_lib, _crypto_lib])
    else
      openssl_dep = disabler()
    endif
  endif
endif

https_cpp_args = []
https_deps = []
if not is_disabler(openssl_dep) and openssl_dep.found()
  https_cpp_args = ['-DCPPHTTPLIB_OPENSSL_SUPPORT']
  https_deps = [openssl_dep]
endif

sqlite3_dep = dependency('sqlite3', required: false, include_type: 'system')
if not sqlite3_dep.found()
  sqlite3_dep = dependency('unofficial-sqlite3', method: 'cmake', modules: ['unofficial::sqlite3::sqlite3'], required: false, include_type: 'system')
endif
if not sqlite3_dep.found()
  sqlite3_dep = cxx.find_library('sqlite3')
endif
nlohmann_json_dep = dependency('nlohmann_json', required: true, include_type: 'system')

# RE2 for linear-time regex (replaces std::regex to prevent ReDoS)
re2_dep = dependency('re2', method: 'cmake', modules: ['re2::re2'], required: false, include_type: 'system')
if not re2_dep.found()
  re2_dep = dependency('re2', required: false, include_type: 'system')
endif
if not re2_dep.found()
  re2_dep = cxx.find_library('re2')
endif

# Build-time embed of vendored ECharts into a generated .cpp containing
# chunked raw string literals (sliced to fit MSVC's 16,380-byte limit on
# raw string literals — error C2026). Symbol: kEChartsJs.
echarts_embed = custom_target(
  'echarts_js_bundle',
  input: 'vendor/echarts.min.js',
  output: 'echarts_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'EChartsJs',
  ],
)

# Build-time embed of vendored Three.js r168 + OrbitControls (PR 4 of
# feat/viz-engine ladder). Same chunked-raw-string pattern as ECharts;
# fragment loader in PR 5 wires `<script type="importmap">` so the
# OrbitControls module's `import ... from 'three'` resolves to the
# vendored file. We ship the ES-module form rather than UMD because
# Three.js dropped UMD in r150+ -- modern releases only publish
# `three.module.min.js`. Symbols: kThreeJs (~685 KB), kThreeOrbitControlsJs (~32 KB).
three_embed = custom_target(
  'three_js_bundle',
  input: 'vendor/three.module.min.js',
  output: 'three_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'ThreeJs',
  ],
)

three_orbit_embed = custom_target(
  'three_orbit_controls_js_bundle',
  input: 'vendor/three-orbit-controls.js',
  output: 'three_orbit_controls_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'ThreeOrbitControlsJs',
  ],
)

# Build-time embed of the Yuzu fleet-viz renderer module (PR 5 + PR 6 of
# feat/viz-engine ladder). Hand-written before PR 6 (~10 KB) when it fit
# under MSVC's 16,380-byte raw-string-literal limit; PR 6 took the bundle
# past that limit, so we now codegen via embed_js.py like ECharts and
# Three.js. Symbol: kYuzuVizJs (std::string).
yuzu_viz_js_embed = custom_target(
  'yuzu_viz_js_bundle',
  input: 'static/yuzu-viz.js',
  output: 'yuzu_viz_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'YuzuVizJs',
  ],
)

# PR 9-pre: per-host renderer module + vendored Cytoscape.js 3.33.3 (MIT).
# Cytoscape ships as ESM minified (cytoscape.esm.min.mjs from the npm
# tarball) so the importmap entry in viz_host_page_ui.cpp can resolve
# `import cytoscape from "cytoscape"`. The renderer uses cytoscape's
# built-in `cose` force-directed layout — no layout extension is vendored
# (the faster `fcose` is a UMD bundle with an external cose-base
# dependency that doesn't resolve cleanly against an ESM importmap).
yuzu_viz_host_js_embed = custom_target(
  'yuzu_viz_host_js_bundle',
  input: 'static/yuzu-viz-host.js',
  output: 'yuzu_viz_host_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'YuzuVizHostJs',
  ],
)

cytoscape_js_embed = custom_target(
  'cytoscape_js_bundle',
  input: 'static/cytoscape.min.js',
  output: 'cytoscape_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'CytoscapeJs',
  ],
)

# Build-time embed of the Yuzu Design System CSS bundle. The source
# kYuzuCss exceeded MSVC's 16,380-byte raw-string-literal limit (C2026)
# after the design-token expansion. Chunking into ~14 KB
# fragments concatenated at static-init time keeps every chunk under
# the limit. Symbol: kYuzuCss (std::string).
yuzu_css_embed = custom_target(
  'yuzu_css_bundle',
  input: 'static/yuzu.css',
  output: 'yuzu_css_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'YuzuCss',
  ],
)

# Build-time embed of vendored Inter variable webfont as a constexpr
# byte array (woff2 binary; cannot use raw string literals). Symbol:
# kInterVariableWoff2 — std::string_view of the bytes.
inter_embed = custom_target(
  'inter_woff2_bundle',
  input: 'vendor/inter/InterVariable.woff2',
  output: 'inter_woff2_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_binary.py'),
    '@INPUT@',
    '@OUTPUT@',
    'InterVariableWoff2',
  ],
)

# Build-time YAML→JSON conversion for shipped Yuzu content. The
# server iterates kBundledDefinitions / kBundledSets on startup and
# upserts them into the instruction store, so charts are populated
# without operator intervention. Sidesteps yaml-cpp on Windows MSVC
# (#625) by doing the parse at build time with PyYAML.
#
# PyYAML is a hard build dependency: the embedded vector is the only
# path by which shipped InstructionDefinitions reach the server (no
# filesystem fallback at runtime), so a missing PyYAML used to silently
# produce a binary with an empty Instructions tab. Probe at configure
# time so the failure surfaces here rather than mid-compile.
embed_python = find_program('python3', 'python')
_yaml_probe = run_command(embed_python, '-c', 'import yaml', check: false)
if _yaml_probe.returncode() != 0
  error(
    'PyYAML is required to embed shipped InstructionDefinitions but is '
    + 'not importable from ' + embed_python.full_path() + '. '
    + 'Install with `pip install pyyaml` (Linux/macOS) or '
    + '`pacman -S python-yaml` (MSYS2). See CLAUDE.md "Instruction Engine".'
  )
endif

content_embed = custom_target(
  'bundled_content',
  output: 'bundled_content.cpp',
  command: [
    embed_python,
    files('scripts/embed_content.py'),
    meson.project_source_root() / 'content',
    '@OUTPUT@',
  ],
  build_always_stale: true,  # always re-scan content/ for edits
)

# Vendored Nayuki QR-Code-generator (MIT, pinned v1.8.0; see
# server/core/vendor/qrcodegen/qrcodegen-NOTICE.txt). Built as its own
# static lib with warnings off so third-party source does not trip our
# warning_level=3 — same isolation the vcpkg deps get via include_type:'system'.
qrcodegen_lib = static_library(
  'qrcodegen',
  files('vendor/qrcodegen/qrcodegen.cpp'),
  include_directories: include_directories('vendor/qrcodegen'),
  override_options: ['warning_level=0', 'werror=false'],
)
qrcodegen_dep = declare_dependency(
  link_with: qrcodegen_lib,
  include_directories: include_directories('vendor/qrcodegen'),
)

# KeyProvider leaf target (ADR-0010, #1320 PR 4, governance arch-S3).
# key_provider.{hpp,cpp} is extracted from yuzu_server_core_lib so the pg/
# substrate (SecretCodec takes a KekProvider&) can grow into its own library
# later without a meson graph cycle: pg → key_provider is a leaf edge, while
# key_provider → server_core would have been a back edge. OpenSSL is required
# here unconditionally (AES-256-GCM KEK wrap/unwrap + SHA-256 check values +
# OPENSSL_cleanse zeroization). A disabler would NOT fail loudly — it would
# silently disable this target and everything that links it (the whole
# server), so guard explicitly (governance build-S1).
if is_disabler(openssl_dep) or not openssl_dep.found()
  error('OpenSSL is required for yuzu_key_provider (ADR-0010 secrets seam); '
        + 'vcpkg.json makes it an unconditional dependency on every platform')
endif
yuzu_key_provider_lib = static_library(
  'yuzu_key_provider',
  files('src/key_provider.cpp'),
  dependencies: [spdlog_dep, openssl_dep],
)
yuzu_key_provider_dep = declare_dependency(
  link_with: yuzu_key_provider_lib,
  dependencies: [openssl_dep],
)

yuzu_server_core_lib = static_library(
  'yuzu_server_core',
  [echarts_embed, three_embed, three_orbit_embed, yuzu_viz_js_embed,
   yuzu_viz_host_js_embed, cytoscape_js_embed,
   yuzu_css_embed, inter_embed, content_embed,
  files(
    'src/server.cpp',
    'src/agent_registry.cpp',
    'src/agent_service_impl.cpp',
    'src/gateway_service_impl.cpp',
    'src/auth.cpp',
    'src/auth_db.cpp',
    'src/auth_routes.cpp',
    'src/mfa_step_up.cpp',
    'src/mfa_qr.cpp',
    'src/totp.cpp',
    'src/auto_approve.cpp',
    'src/cidr_match.cpp',
    'src/dashboard_ui.cpp',
    'src/chargen_ui.cpp',
    'src/procfetch_ui.cpp',
    'src/login_ui.cpp',
    'src/settings_ui.cpp',
    'src/settings_routes.cpp',
    'src/plugin_signing_helpers.cpp',
    'src/nvd_db.cpp',
    'src/nvd_client.cpp',
    'src/nvd_sync.cpp',
    'src/update_registry.cpp',
    'src/response_store.cpp',
    'src/bundle_service.cpp',
    'src/bundle_orchestrator.cpp',
    'src/audit_store.cpp',
    'src/tag_store.cpp',
    'src/scope_engine.cpp',
    'src/yaml_scan.cpp',
    'src/scope_yaml.cpp',
    'src/analytics_event_store.cpp',
    'src/analytics_sinks.cpp',
    'src/data_export.cpp',
    'src/instruction_db_pool.cpp',
    'src/instruction_store.cpp',
    'src/execution_tracker.cpp',
    'src/execution_event_bus.cpp',
    'src/fleet_topology_store.cpp',
    'src/heartbeat_ingestion.cpp',
    'src/approval_manager.cpp',
    'src/schedule_engine.cpp',
    'src/help_ui.cpp',
    'src/instruction_ui.cpp',
    'src/tar_page_ui.cpp',
    'src/result_sets_ui.cpp',
    'src/rbac_store.cpp',
    'src/oidc_provider.cpp',
    'src/error_codes.cpp',
    'src/result_envelope.cpp',
    'src/concurrency_manager.cpp',
    'src/legacy_shim.cpp',
    'src/management_group_store.cpp',
    'src/api_token_store.cpp',
    'src/secure_random.cpp',
    'src/quarantine_store.cpp',
    'src/result_set_store.cpp',
    'src/result_set_matcher.cpp',
    'src/result_set_maintenance.cpp',
    'src/policy_store.cpp',
    'src/policy_evaluator.cpp',
    'src/guaranteed_state_store.cpp',
    'src/baseline_store.cpp',
    'src/guardian_push_builder.cpp',
    'src/guardian_ingest.cpp',
    'src/guardian_resilience_schema.cpp',
    'src/guardian_rule_spec.cpp',
    'src/guardian_schema_registry.cpp',
    'src/guardian_form_render.cpp',
    'src/dex_alert_router.cpp',
    'src/dex_blast_radius.cpp',
    'src/runtime_config_store.cpp',
    'src/custom_properties_store.cpp',
    'src/mcp_server.cpp',
    'src/rest_api_v1.cpp',
    'src/compliance_routes.cpp',
    'src/guardian_routes.cpp',
    'src/dex_routes.cpp',
    'src/dex_perf_model.cpp',
    'src/dex_app_perf_model.cpp',
    'src/dex_app_perf_ui.cpp',
    'src/dex_perf_ui.cpp',
    'src/network_perf_model.cpp',
    'src/network_routes.cpp',
    'src/network_ui.cpp',
    'src/device_routes.cpp',
    'src/device_ui.cpp',
    'src/inventory_routes.cpp',
    'src/inventory_ui.cpp',
    'src/software_catalog_rollup.cpp',
    'src/preflight_routes.cpp',
    'src/preflight_ui.cpp',
    'src/preflight_eval.cpp',
    'src/preflight_run_store.cpp',
    'src/preflight_runner.cpp',
    'src/deployment_routes.cpp',
    'src/deployment_ui.cpp',
    'src/deployment_run_store.cpp',
    'src/deployment_engine.cpp',
    'src/tar_process_tree.cpp',
    'src/tar_tree_routes.cpp',
    'src/dashboard_routes.cpp',
    'src/workflow_routes.cpp',
    'src/notification_routes.cpp',
    'src/webhook_routes.cpp',
    'src/offload_routes.cpp',
    'src/discovery_routes.cpp',
    'src/viz_routes.cpp',
    'src/viz_page_ui.cpp',
    'src/viz_host_page_ui.cpp',
    'src/compliance_ui.cpp',
    'src/guardian_ui.cpp',
    'src/guardian_page_ui.cpp',
    'src/cel_eval.cpp',
    'src/compliance_eval.cpp',
    'src/workflow_engine.cpp',
    'src/product_pack_store.cpp',
    'src/app_perf_daily_store.cpp',
    'src/app_perf_fleet_store.cpp',
    'src/app_perf_group_reader.cpp',
    'src/app_perf_ingestion.cpp',
    'src/app_perf_rollup.cpp',
    'src/inventory_ingestion.cpp',
    'src/inventory_store.cpp',
    'src/software_inventory_store.cpp',
    'src/offline_endpoint_store.cpp',
    'src/notification_store.cpp',
    'src/webhook_store.cpp',
    'src/offload_target_store.cpp',
    'src/directory_sync.cpp',
    'src/patch_manager.cpp',
    'src/deployment_store.cpp',
    'src/discovery_store.cpp',
    'src/inventory_eval.cpp',
    'src/device_token_store.cpp',
    'src/software_deployment_store.cpp',
    'src/license_store.cpp',
    'src/topology_ui.cpp',
    'src/statistics_ui.cpp',
    # css_bundle.cpp removed in favour of build-time chunked embed (Gate 4
    # cpp-B1: kYuzuCss exceeds MSVC's 16,380-byte raw-string-literal limit).
    # Source CSS lives at server/core/static/yuzu.css; embed_js.py emits
    # yuzu_css_bundle.cpp with the chunked literal pattern.
    'src/static_js_bundle.cpp',
    'src/charts_js_bundle.cpp',
    'src/visualization_engine.cpp',
    'src/response_templates_engine.cpp',
    'src/icons_svg.cpp',
    'src/migration_runner.cpp',
    # Postgres substrate (ADR-0006/0008, #1320 PR 1): RAII owners + shared
    # pool + migration runner under src/pg/. Header pg_raii.hpp is
    # header-only; canary_main.cpp is the separate yuzu_pg_canary exe below.
    'src/pg/pg_pool.cpp',
    'src/pg/pg_migration_runner.cpp',
    # SecretCodec (ADR-0010, #1320 PR 4): app-side envelope encryption for
    # secret columns. Depends on the yuzu_key_provider leaf target above.
    'src/pg/secret_codec.cpp',
    'src/rate_limiter.cpp',
    'src/cert_reloader.cpp',
    'src/x509_ca.cpp',
    # key_provider.cpp lives in the yuzu_key_provider leaf target above
    # (ADR-0010 arch-S3); the dep below carries it.
    'src/ca_store.cpp',
    'src/default_certs.cpp',
    'src/ca_routes.cpp',
    'src/security_headers.cpp',
  )],
  include_directories: ['include'],
  cpp_args: https_cpp_args + ['-DCPPHTTPLIB_LISTEN_BACKLOG=128'] + (cxx.get_id() == 'msvc' ? ['/bigobj'] : []),
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep,
                 sqlite3_dep, nlohmann_json_dep, re2_dep, qrcodegen_dep,
                 libpq_dep, yuzu_key_provider_dep] + auth_crypto_deps + https_deps,
)

yuzu_server_core_dep = declare_dependency(
  link_with: yuzu_server_core_lib,
  include_directories: include_directories('include'),
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep,
                 sqlite3_dep, nlohmann_json_dep, re2_dep, qrcodegen_dep,
                 libpq_dep, yuzu_key_provider_dep] + auth_crypto_deps + https_deps,
)

executable(
  'yuzu-server',
  files('src/main.cpp'),
  dependencies: [yuzu_server_core_dep, cli11_dep] + auth_crypto_deps,
  install: true,
)

# Postgres link canary (#1317 F0, ADR-0008): proves libpq builds at the pinned
# vcpkg baseline and links on MSVC with no LNK-class errors (the #375 lesson).
# Linkage is static on Linux/macOS, dynamic DLL on Windows (see the libpq_dep
# comment in the root meson.build and the ADR-0008 Correction). The F1
# substrate (#1320 PR 1) folded its body onto the pg_raii owners, but the
# TARGET stays: the CI link-provenance assertions on all four Tier-1 legs
# (ldd/otool/dumpbin in ci.yml) inspect this binary path. Do not remove or
# rename without updating those workflow steps.
executable(
  'yuzu_pg_canary',
  files('src/pg/canary_main.cpp'),
  dependencies: [libpq_dep],
  install: false,
)
