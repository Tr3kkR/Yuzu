tar_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep, sqlite3_dep, nlohmann_dep]
tar_cpp_args = []

if host_machine.system() == 'windows'
  tar_deps += cxx.find_library('advapi32')
  tar_deps += cxx.find_library('iphlpapi')
  tar_deps += cxx.find_library('ws2_32')
  tar_deps += cxx.find_library('wtsapi32')
  tar_deps += cxx.find_library('tdh')      # ETW event decoding (tar_proc_etw, tar_module_etw)
  tar_deps += cxx.find_library('wintrust') # WinVerifyTrust — image signing (tar_module_etw)
  tar_deps += cxx.find_library('crypt32')  # CryptQueryObject — signer extraction (tar_module_etw)
elif host_machine.system() == 'darwin'
  # Endpoint Security process stream (tar_proc_es). The ES framework ships only
  # with the FULL Xcode SDK, not the Command Line Tools SDK, so detect it: where
  # present, compile the real ES client (-DYUZU_HAVE_ENDPOINT_SECURITY) and link
  # the framework + libbsm (audit_token_to_pid / audit_token_to_ruid); where
  # absent, tar_proc_es.cpp compiles its no-op path and the agent falls back to
  # the sysctl process poll. See docs/darwin-compat.md.
  es_dep = dependency('appleframeworks', modules: ['EndpointSecurity'], required: false, include_type: 'system')
  if es_dep.found()
    tar_deps += es_dep
    tar_deps += cxx.find_library('bsm')
    # -fblocks: tar_proc_es.cpp passes an Objective-C block literal (^{...}) to
    # es_new_client. Apple Clang does NOT enable blocks by default for a .cpp TU,
    # so without this the real ES path fails to compile on a full-Xcode build.
    tar_cpp_args += ['-DYUZU_HAVE_ENDPOINT_SECURITY', '-fblocks']
  else
    message('TAR: EndpointSecurity framework not found (full Xcode SDK required) — '
            + 'process streaming compiles as a no-op; agent uses the sysctl poll.')
  endif
endif

shared_library(
  'tar',
  files(
    'src/tar_plugin.cpp',
    'src/tar_db.cpp',
    'src/tar_diff.cpp',
    'src/tar_schema_registry.cpp',
    'src/tar_aggregator.cpp',
    'src/tar_sql_executor.cpp',
    'src/tar_network_collector.cpp',
    'src/tar_perf.cpp',
    'src/tar_proc_perf.cpp',
    'src/tar_proc_stream.cpp',
    'src/tar_proc_etw.cpp',
    'src/tar_proc_es.cpp',
    'src/tar_module_etw.cpp',
    'src/tar_service_collector.cpp',
    'src/tar_user_collector.cpp',
    'src/tar_fleet_snapshot.cpp',
  ),
  name_prefix: '',
  cpp_args: tar_cpp_args,
  dependencies: tar_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
