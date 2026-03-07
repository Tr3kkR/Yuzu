project(
  'yuzu',
  'cpp',
  version: '0.1.0',
  license: 'Apache-2.0',
  meson_version: '>=1.3.0',
  default_options: [
    'cpp_std=c++latest',
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
if host_machine.system() == 'windows'
  add_project_arguments('/wd4251','/wd4127','/wd4275', language: 'cpp')
endif

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
  endif
endif

# ── Server ────────────────────────────────────────────────────────────────────
if build_server
  subdir('server/core')
  subdir('server/gateway')
endif

# ── Tests ─────────────────────────────────────────────────────────────────────
if build_tests
  subdir('tests')
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
