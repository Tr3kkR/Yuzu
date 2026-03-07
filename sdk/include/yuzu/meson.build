# Generate version.hpp from template into the build-dir mirror of this
# directory (<builddir>/sdk/include/yuzu/version.hpp), so that
# include_directories('include') from sdk/meson.build picks it up and
# #include <yuzu/version.hpp> resolves correctly.
version_hpp = configure_file(
  input:  'version.hpp.in',
  output: 'version.hpp',
  configuration: version_conf,
)
