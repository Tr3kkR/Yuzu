# Generate version.hpp into <builddir>/sdk/include/yuzu/ so that
# include_directories('include') exposes both source and build trees.
subdir('include/yuzu')

yuzu_sdk_dep = declare_dependency(
  include_directories: include_directories('include'),
  sources: version_hpp,
)
