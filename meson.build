project(
  'yuzu',
  'cpp',
  version: '0.11.0',
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
    '-fstack-protector-strong',
    language: 'cpp',
  )
  # FORTIFY_SOURCE requires optimisation; only enable for release builds.
  # Undef first to avoid -Wmacro-redefined on distros that set it in system headers.
  if get_option('buildtype') != 'debug'
    add_project_arguments('-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=2', language: 'cpp')
  endif
  # Full RELRO + immediate binding — makes GOT/PLT read-only after load.
  # Only ELF platforms; Apple's ld64 does not support -z flags.
  if host_os != 'darwin'
    add_project_link_arguments('-Wl,-z,relro,-z,now', language: 'cpp')
  endif
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

# ── Git-derived version tag ──────────────────────────────────────────────────
# Produces a header that is rebuilt whenever HEAD changes, so the version
# string always reflects the current commit (e.g. v0.5.0-42-gabcdef).
vcs_tag(
  input:   'sdk/include/yuzu/git_version.hpp.in',
  output:  'git_version.hpp',
  command: git.found() ? [git, 'describe', '--tags', '--always', '--dirty'] : ['echo', 'v' + meson.project_version()],
  fallback: 'v' + meson.project_version(),
)

# ── Feature summary ───────────────────────────────────────────────────────────
build_agent    = get_option('build_agent')
build_server   = get_option('build_server')
build_examples = get_option('build_examples')
build_tests    = get_option('build_tests')

# ── Dependencies ──────────────────────────────────────────────────────────────
# All third-party includes are marked `include_type: 'system'` so the compiler
# treats them as `-isystem` paths and suppresses their warnings. This is
# load-bearing for build log readability — without it the gRPC / abseil /
# protobuf deprecation warnings drown out our own code warnings and force a
# grep-for-error filter workflow. Our own code remains under `warning_level=3`.
if host_os == 'windows'
  # ──────────────────────────────────────────────────────────────────────
  # #375 option D: bypass meson's cmake dep for protobuf/grpc on Windows.
  # ──────────────────────────────────────────────────────────────────────
  # Meson's cmake dependency translator reads IMPORTED_LOCATION_RELEASE
  # from vcpkg's imported targets regardless of --buildtype=debug, so a
  # debug build with `dependency('protobuf', method: 'cmake', ...)` would
  # link release-CRT static libs into /MDd debug user code and trip
  # dozens of LNK2038 RuntimeLibrary mismatches. Dropping the triplet's
  # static-linkage override doesn't help either — vcpkg's grpc port
  # forces static regardless, and grpc.lib's embedded abseil template
  # symbols collide with abseil_dll.lib exports on release builds,
  # producing LNK2005 duplicate symbol errors. The only configuration
  # that threads both needles is static linkage in triplets/x64-windows.cmake
  # + this explicit find_library() wiring with build-type-conditional
  # search dirs. Keep BOTH halves in sync; neither can be simplified
  # alone. Full diagnosis:
  #   .claude/agents/build-ci.md "Windows MSVC static-link history and #375"
  # Strategic escape (P1): #376 "Migrate transport off gRPC to QUIC".

  _cxx = meson.get_compiler('cpp')
  _vcpkg_root_win = meson.project_source_root() / 'vcpkg_installed' / 'x64-windows'
  # include_directories() rejects absolute paths inside the source tree,
  # so the include dir has to be a relative-to-source-root string.
  # Headers are the same across debug and release variants, so this
  # points at the shared include/ regardless of buildtype.
  _vcpkg_include_win_rel = 'vcpkg_installed/x64-windows/include'
  if get_option('buildtype') == 'debug'
    _vcpkg_lib_win = _vcpkg_root_win / 'debug' / 'lib'
    _pbd = 'd'   # vcpkg convention: libprotobufd.lib / libprotobuf-lited.lib / libprotocd.lib / libupbd.lib
  else
    _vcpkg_lib_win = _vcpkg_root_win / 'lib'
    _pbd = ''
  endif

  # Enumerate absl_*.lib at configure time via python glob. The transitive
  # absl dep closure of protobuf+grpc is ~40 libs and shifts between
  # abseil versions; hand-listing would be a maintenance burden. Enumerating
  # here means a vcpkg abseil bump doesn't need a parallel meson.build edit.
  _py = find_program('python3')
  _absl_enum = run_command(
    _py, '-c',
    'import glob, os, sys\n' +
    'for p in sorted(glob.glob(os.path.join(sys.argv[1], "absl_*.lib"))):\n' +
    '    print(os.path.splitext(os.path.basename(p))[0])\n',
    _vcpkg_lib_win,
    check: true,
  )
  _absl_names = _absl_enum.stdout().strip().split('\n')
  if _absl_names.length() == 0 or (_absl_names.length() == 1 and _absl_names[0] == '')
    error('#375 option D: no absl_*.lib files found in @0@ — vcpkg install may be incomplete'.format(_vcpkg_lib_win))
  endif
  message('#375 option D: enumerated @0@ abseil libs from @1@'.format(_absl_names.length(), _vcpkg_lib_win))
  _absl_deps = []
  foreach _absl_name : _absl_names
    _absl_deps += _cxx.find_library(_absl_name, dirs: [_vcpkg_lib_win], required: true)
  endforeach

  # Protobuf core + transitive utf8_range.
  _libprotobuf      = _cxx.find_library('libprotobuf'      + _pbd, dirs: [_vcpkg_lib_win], required: true)
  _libprotobuf_lite = _cxx.find_library('libprotobuf-lite' + _pbd, dirs: [_vcpkg_lib_win], required: true)
  _libprotoc        = _cxx.find_library('libprotoc'        + _pbd, dirs: [_vcpkg_lib_win], required: true)
  _libupb           = _cxx.find_library('libupb'           + _pbd, dirs: [_vcpkg_lib_win], required: true)
  _libutf8_range    = _cxx.find_library('utf8_range',              dirs: [_vcpkg_lib_win], required: true)
  _libutf8_validity = _cxx.find_library('utf8_validity',           dirs: [_vcpkg_lib_win], required: true)

  # gRPC core + C++ API + transitive re2 / c-ares / address_sorting.
  _libgrpc             = _cxx.find_library('grpc',             dirs: [_vcpkg_lib_win], required: true)
  _libgrpcpp           = _cxx.find_library('grpc++',           dirs: [_vcpkg_lib_win], required: true)
  _libgpr              = _cxx.find_library('gpr',              dirs: [_vcpkg_lib_win], required: true)
  _libaddress_sorting  = _cxx.find_library('address_sorting',  dirs: [_vcpkg_lib_win], required: true)
  _libre2              = _cxx.find_library('re2',              dirs: [_vcpkg_lib_win], required: true)
  _libcares            = _cxx.find_library('cares',            dirs: [_vcpkg_lib_win], required: true)

  # OpenSSL — grpc.lib has unresolved references to BIO_*, EVP_*, PEM_*,
  # X509_*, OPENSSL_sk_* that only libssl + libcrypto can satisfy. vcpkg's
  # grpc port compiles its TLS / JWT / SPIFFE / PEM code paths against
  # OpenSSL headers regardless of any triplet or manifest hint that it
  # "should" use schannel — the schannel path was never wired up in the
  # upstream grpc port. See CLAUDE.md `## vcpkg` section and .claude/agents/
  # build-ci.md "Windows MSVC static-link history and #375" for history.
  _libssl    = _cxx.find_library('libssl',    dirs: [_vcpkg_lib_win], required: true)
  _libcrypto = _cxx.find_library('libcrypto', dirs: [_vcpkg_lib_win], required: true)

  # Construct the meson dep objects yuzu's build graph consumes. These
  # REPLACE the `dependency('protobuf', method: 'cmake')` / `dependency('gRPC',
  # method: 'cmake')` calls that Linux/macOS use — those paths are
  # unreachable on Windows.
  protobuf_dep = declare_dependency(
    include_directories: include_directories(_vcpkg_include_win_rel, is_system: true),
    dependencies: [
      _libprotobuf, _libprotobuf_lite, _libprotoc, _libupb,
      _libutf8_range, _libutf8_validity,
    ] + _absl_deps,
  )
  grpcpp_dep = declare_dependency(
    include_directories: include_directories(_vcpkg_include_win_rel, is_system: true),
    dependencies: [
      _libgrpcpp, _libgrpc, _libgpr, _libaddress_sorting,
      _libre2, _libcares,
      _libssl, _libcrypto,
      # grpc transitively uses protobuf and upb; include them so consumers
      # that only pull in grpcpp_dep still see protobuf's symbols.
      _libprotobuf, _libprotobuf_lite, _libupb, _libutf8_range, _libutf8_validity,
    ] + _absl_deps,
  )
else
  # Linux/macOS: meson's cmake dep method works correctly because gcc/clang
  # don't have MSVC's runtime-library variant ABI — debug user code can
  # safely link against release-built .a static libs, and the cmake dep
  # translator's IMPORTED_LOCATION_RELEASE bias is harmless.
  grpcpp_dep = dependency('gRPC', method: 'cmake', modules: ['gRPC::grpc++'],
    required: false, include_type: 'system')
  if not grpcpp_dep.found()
    grpcpp_dep = dependency('grpc++', method: 'pkg-config', required: true,
      include_type: 'system')
  endif
  protobuf_dep = dependency('protobuf', method: 'cmake', modules: ['protobuf::libprotobuf'],
    required: false, include_type: 'system')
  if not protobuf_dep.found()
    protobuf_dep = dependency('protobuf', method: 'pkg-config', required: true,
      include_type: 'system')
  endif
endif
add_project_arguments('-DSPDLOG_COMPILED_LIB', language: 'cpp')
spdlog_dep      = dependency('spdlog',        required: true, include_type: 'system')
nlohmann_dep    = dependency('nlohmann_json', required: true, include_type: 'system')
cli11_dep       = dependency('CLI11', method: 'cmake', modules: ['CLI11::CLI11'],
  required: true, include_type: 'system')
httplib_dep     = dependency('httplib', required: false, include_type: 'system')
if not httplib_dep.found()
  httplib_dep   = dependency('cpp-httplib', required: true, include_type: 'system')
endif
sqlite3_dep     = dependency('SQLite3', method: 'cmake', modules: ['SQLite::SQLite3'],
  required: true, include_type: 'system')

# macOS frameworks needed by gRPC, abseil, and cpp-httplib
if host_os == 'darwin'
  corefoundation_dep = dependency('appleframeworks', modules: ['CoreFoundation', 'Security', 'CFNetwork'])
  grpcpp_dep  = declare_dependency(dependencies: [grpcpp_dep, corefoundation_dep])
  httplib_dep = declare_dependency(dependencies: [httplib_dep, corefoundation_dep])
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
    subdir('agents/plugins/asset_tags')
    subdir('agents/plugins/quarantine')
    subdir('agents/plugins/certificates')
    subdir('agents/plugins/ioc')
    subdir('agents/plugins/storage')
    subdir('agents/plugins/interaction')
    subdir('agents/plugins/agent_logging')
    subdir('agents/plugins/http_client')
    subdir('agents/plugins/content_dist')
    subdir('agents/plugins/registry')
    subdir('agents/plugins/wmi')
    subdir('agents/plugins/tar')
    subdir('agents/plugins/wifi')
    subdir('agents/plugins/wol')
    subdir('agents/plugins/discovery')
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
  # ── Gateway tests (EUnit + Common Test) ──────────────────────────────
  _gw_test_script = meson.project_source_root() / 'scripts' / 'test_gateway.py'
  _python3 = find_program('python3')
  # The test script prepends OTP 28 / rebar3 paths to PATH internally,
  # handling the case where Meson inherits a system PATH with OTP 25.
  test('gateway eunit',
    _python3,
    args: [_gw_test_script, _gw_src, 'eunit'],
    suite: 'gateway',
    timeout: 120,
  )
  test('gateway ct',
    _python3,
    args: [_gw_test_script, _gw_src, 'ct'],
    suite: 'gateway',
    timeout: 300,
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
