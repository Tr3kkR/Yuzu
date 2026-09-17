# cert_scan — SSL/TLS certificate and private-key discovery plugin.
#
# Reuses certificates_x509.hpp (the certificates plugin's pure, dependency-
# free-of-plugin-state libcrypto PEM/DER parser) directly via a relative
# include_directories entry rather than duplicating it -- that header was
# already designed to operate only on in-memory bytes handed in by a
# caller, with no assumption about which plugin owns the I/O around it, so
# it is a genuine candidate for shared reuse without modification.
#
# openssl_dep is declared locally (not reused from agents/core/meson.build's
# agent_openssl_dep, or from the certificates plugin's own cert_deps) because
# Meson's subdir() scoping does not propagate a subdir-local variable to a
# SIBLING subdir -- each subdir that needs OpenSSL declares its own
# dependency() call. Needed unconditionally on every OS here (unlike the
# certificates plugin's Windows/!Windows split, which only needs OpenSSL off
# Windows for its own keychain/store reads) because cert_scan parses
# PEM/DER file bytes found in home directories the same way on all three
# platforms -- there is no OS certificate-store API involved at all.
cert_scan_openssl_dep = dependency('openssl', required: true, include_type: 'system')

shared_library(
  'cert_scan',
  files('src/cert_scan_plugin.cpp'),
  name_prefix: '',
  include_directories: [
    include_directories('../certificates/src'),
    include_directories('../../shared'),  # win_profiles.hpp / user_profile_model.hpp (Windows home-directory discovery)
  ],
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, cert_scan_openssl_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
