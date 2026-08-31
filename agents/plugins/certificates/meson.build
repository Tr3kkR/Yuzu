# Platform-specific crypto dependencies for certificate store access
cert_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
cert_cpp_args = []
if host_machine.system() == 'windows'
  cert_deps += cxx.find_library('crypt32')
else
  # Linux/macOS: in-process libcrypto X509 parse (certificates_x509.hpp,
  # WP-B) replaces the `openssl x509` subprocess entirely on Linux and backs
  # the macOS SecItem DER decode below -- same shape as
  # agents/plugins/procfetch/meson.build's non-Windows openssl dependency.
  cert_deps += dependency('openssl', required: true, include_type: 'system')
endif

if host_machine.system() == 'darwin'
  # System.keychain / SystemRootCertificates.keychain rung-1 SecItem read
  # (WP-B). required: false + a -D flag, same shape as
  # agents/plugins/users/meson.build's YUZU_HAVE_SYSTEMCONFIGURATION gate, so
  # a box without the Security framework still builds an honest fallback
  # (read_keychain_secitem() compiles to a no-op returning
  # SecItemKeychainResult{.ok = false}) instead of failing configure. The
  # login-keychain read stays on its existing `security` subprocess path
  # either way (rung-2 pre-split argv since #3406 -- see
  # build_login_keychain_read_argv()).
  security_dep = dependency('appleframeworks', modules: ['Security', 'CoreFoundation'],
                            required: false, include_type: 'system')
  if security_dep.found()
    cert_deps += security_dep
    cert_cpp_args += ['-DYUZU_HAVE_SECURITY_FRAMEWORK']
  else
    message('CERTIFICATES: Security framework not found -- System.keychain/'
            + 'SystemRootCertificates.keychain read compiles as a no-op; '
            + 'falls back to the not_available|... sentinel.')
  endif
endif

shared_library(
  'certificates',
  files('src/certificates_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # macos_console_user.hpp
  cpp_args: cert_cpp_args,
  dependencies: cert_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
