project(
  'yuzu',
  'cpp',
  version: '0.1.0',
  license: 'Apache-2.0',
  meson_version: '>=1.3.0',
  default_options: [
    'cpp_std=c++23',
    'warning_level=3',
    'werror=false',
    'default_library=shared',
    'b_pie=true',
  ],
)

# ── Compiler / host info ──────────────────────────────────────────────────────
cxx = meson.get_compiler('cpp')
host_os  = host_machine.system()   # 'linux', 'windows', 'darwin'
host_cpu = host_machine.cpu_family() # 'x86_64', 'aarch64', ...
if cxx.get_id() == 'msvc'
  add_project_arguments(
    '/std:c++latest',           # upgrade beyond c++23 default for MSVC
    '/wd4251', '/wd4127', '/wd4275',
    '/permissive-', '/Zc:__cplusplus', '/utf-8',
    language: 'cpp',
  )
else
  add_project_arguments(
    '-Wno-unused-parameter',
    '-fvisibility=hidden',
    language: 'cpp',
  )
  if cxx.get_id() == 'clang'
    add_project_arguments('-Wno-gnu-zero-variadic-macro-arguments', language: 'cpp')
  endif
endif

# ── Build number from git ────────────────────────────────────────────────────
git = find_program('git', required: false)
if git.found()
  git_count = run_command(git, 'rev-list', '--count', 'HEAD', check: false)
  yuzu_build_number = git_count.returncode() == 0 ? git_count.stdout().strip() : '0'
  git_hash = run_command(git, 'rev-parse', '--short', 'HEAD', check: false)
  yuzu_git_commit_hash = git_hash.returncode() == 0 ? git_hash.stdout().strip() : 'unknown'
else
  yuzu_build_number = '0'
  yuzu_git_commit_hash = 'unknown'
endif

version_conf = configuration_data()
version_conf.set('PROJECT_VERSION_MAJOR', meson.project_version().split('.')[0])
version_conf.set('PROJECT_VERSION_MINOR', meson.project_version().split('.')[1])
version_conf.set('PROJECT_VERSION_PATCH', meson.project_version().split('.')[2])
version_conf.set('YUZU_BUILD_NUMBER', yuzu_build_number)
version_conf.set('YUZU_GIT_COMMIT_HASH', yuzu_git_commit_hash)
version_conf.set('PROJECT_VERSION', meson.project_version())

# ── Feature summary ───────────────────────────────────────────────────────────
build_agent    = get_option('build_agent')
build_server   = get_option('build_server')
build_examples = get_option('build_examples')
build_tests    = get_option('build_tests')

# ── Dependencies ──────────────────────────────────────────────────────────────
grpcpp_dep = dependency('gRPC', method: 'cmake', modules: ['gRPC::grpc++'], required: true)
protobuf_dep = dependency('protobuf', method: 'cmake', modules: ['protobuf::libprotobuf'], required: true)
add_project_arguments('-DSPDLOG_COMPILED_LIB', language: 'cpp')
spdlog_dep      = dependency('spdlog',        required: true)
nlohmann_dep    = dependency('nlohmann_json', required: true)
cli11_dep       = dependency('CLI11',         required: true)
httplib_dep     = dependency('httplib',   required: true)
sqlite3_dep     = dependency('SQLite3', method: 'cmake', modules: ['SQLite::SQLite3'], required: true)

# macOS frameworks needed by gRPC, abseil, and cpp-httplib
if host_os == 'darwin'
  corefoundation_dep = dependency('appleframeworks', modules: ['CoreFoundation', 'Security', 'CFNetwork'])
  grpcpp_dep = declare_dependency(dependencies: [grpcpp_dep, corefoundation_dep])
endif

# ── Proto codegen ─────────────────────────────────────────────────────────────
subdir('proto')

# ── SDK ───────────────────────────────────────────────────────────────────────
subdir('sdk')

# ── Agent ─────────────────────────────────────────────────────────────────────
if build_agent
  subdir('agents/core')
  if build_examples
    subdir('agents/plugins/example')
    subdir('agents/plugins/chargen')
    subdir('agents/plugins/procfetch')
    subdir('agents/plugins/netstat')
    subdir('agents/plugins/sockwho')
    subdir('agents/plugins/status')
    subdir('agents/plugins/device_identity')
    subdir('agents/plugins/os_info')
    subdir('agents/plugins/hardware')
    subdir('agents/plugins/users')
    subdir('agents/plugins/installed_apps')
    subdir('agents/plugins/msi_packages')
    subdir('agents/plugins/network_config')
    subdir('agents/plugins/diagnostics')
    subdir('agents/plugins/agent_actions')
    subdir('agents/plugins/processes')
    subdir('agents/plugins/services')
    subdir('agents/plugins/filesystem')
    subdir('agents/plugins/windows_updates')
    subdir('agents/plugins/event_logs')
    subdir('agents/plugins/sccm')
    subdir('agents/plugins/script_exec')
    subdir('agents/plugins/software_actions')
    subdir('agents/plugins/network_diag')
    subdir('agents/plugins/network_actions')
    subdir('agents/plugins/firewall')
    subdir('agents/plugins/antivirus')
    subdir('agents/plugins/bitlocker')
    subdir('agents/plugins/vuln_scan')
    subdir('agents/plugins/tags')
  endif
endif

# ── Server ────────────────────────────────────────────────────────────────────
if build_server
  subdir('server/core')
endif

# ── Tests ─────────────────────────────────────────────────────────────────────
if build_tests
  subdir('tests')
endif

# ── Erlang Gateway (optional — requires rebar3 + Erlang/OTP) ─────────────
_rebar3 = find_program('rebar3', required: false)
if _rebar3.found()
  _gw_src = meson.project_source_root() / 'gateway'
  _gw_build_script = meson.project_source_root() / 'scripts' / 'build_gateway.py'
  # rebar3 must run from inside the gateway/ directory.
  # We use a Python wrapper instead of 'cmd /c cd ... && rebar3 compile'
  # because Ninja quotes compound commands as a single argument, which
  # breaks cmd.exe on Windows.
  custom_target('gateway',
    command: [find_program('python3'), _gw_build_script, _gw_src],
    output: '.gateway_built',
    build_always_stale: true,
    build_by_default: true,
  )
  message('Erlang gateway: enabled (rebar3 found)')
else
  message('Erlang gateway: skipped (rebar3 not found)')
endif

# ── Deploy DLLs (Windows) ────────────────────────────────────────────────
# Copies vcpkg dependency DLLs alongside executables and gathers plugin
# DLLs into builddir/plugins/ so the agent can find them at runtime.
if host_machine.system() == 'windows'
  _python3 = find_program('python3')
  _deploy_script = meson.project_source_root() / 'scripts' / 'deploy_build_dlls.py'
  _build_root = meson.project_build_root()

  # Derive the vcpkg DLL directory from cmake_prefix_path so we don't
  # depend on VCPKG_ROOT being set in every environment (e.g. CLion).
  _vcpkg_bin = ''
  _cmake_prefixes = get_option('cmake_prefix_path')
  foreach _prefix : _cmake_prefixes
    if _vcpkg_bin == ''
      if get_option('buildtype') == 'debug' or get_option('buildtype') == 'debugoptimized'
        _vcpkg_bin = _prefix / 'debug' / 'bin'
      else
        _vcpkg_bin = _prefix / 'bin'
      endif
    endif
  endforeach

  _deploy_args = ['--build-root', _build_root, '--triplet', 'x64-windows']
  if _vcpkg_bin != ''
    _deploy_args += ['--vcpkg-bin', _vcpkg_bin]
  endif
  if get_option('buildtype') == 'debug' or get_option('buildtype') == 'debugoptimized'
    _deploy_args += ['--debug']
  endif

  # Run at configure time so a fresh setup has all DLLs immediately
  run_command(_python3, _deploy_script, _deploy_args, check: false)

  # Run at build time so rebuilt plugins are always copied to plugins/
  custom_target('deploy_dlls',
    command: [_python3, _deploy_script] + _deploy_args,
    output: '.dlls_deployed',
    build_always_stale: true,
    build_by_default: true,
  )
endif

# ── Summary ───────────────────────────────────────────────────────────────────
summary({
  'Agent':    build_agent,
  'Server':   build_server,
  'Examples': build_examples,
  'Tests':    build_tests,
}, section: 'Components')

summary({
  'OS':  host_os,
  'CPU': host_cpu,
}, section: 'Platform')
