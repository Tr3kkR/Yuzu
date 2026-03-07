# Locate protoc and grpc_cpp_plugin.  When PATH doesn't include the vcpkg
# tools directories (e.g. CLion builds), fall back to the vcpkg install tree
# using cmake_prefix_path (set automatically by vcpkg toolchain integration).
_protoc_extra_dirs = []
_grpc_extra_dirs   = []
_cmake_prefixes = get_option('cmake_prefix_path')
foreach _prefix : _cmake_prefixes
  _protoc_extra_dirs += _prefix / 'tools' / 'protobuf'
  _grpc_extra_dirs   += _prefix / 'tools' / 'grpc'
endforeach

protoc = find_program('protoc',
  dirs: _protoc_extra_dirs,
  required: true,
)
grpc_cpp_plugin = find_program('grpc_cpp_plugin',
  dirs: _grpc_extra_dirs,
  required: true,
)

proto_root = meson.current_source_dir()

gen = custom_target(
    'all_proto_gen',
    input: [
        proto_root / 'yuzu/common/v1/common.proto',
        proto_root / 'yuzu/agent/v1/agent.proto',
        proto_root / 'yuzu/server/v1/management.proto',
    ],
    output: [
        'common.pb.cc', 'common.pb.h', 'common.grpc.pb.cc', 'common.grpc.pb.h',
        'agent.pb.cc',  'agent.pb.h',  'agent.grpc.pb.cc',  'agent.grpc.pb.h',
        'management.pb.cc', 'management.pb.h', 'management.grpc.pb.cc', 'management.grpc.pb.h',
    ],
    command: [
        find_program('python3', 'python'),
        files('gen_proto.py'),
        '@OUTDIR@',
        protoc.full_path(),
        grpc_cpp_plugin.full_path(),
        proto_root,
        proto_root / 'yuzu/common/v1/common.proto',
        proto_root / 'yuzu/agent/v1/agent.proto',
        proto_root / 'yuzu/server/v1/management.proto',
    ],
)

gen_srcs = [gen[0], gen[2], gen[4], gen[6], gen[8], gen[10]]
gen_hdrs = [gen[1], gen[3], gen[5], gen[7], gen[9], gen[11]]

yuzu_proto_lib = static_library(
    'yuzu_proto',
    gen_srcs,
    cpp_args: ['/wd4100','/wd4267','/wd4244','/wd4458','/wd4018','/wd4996'],
    include_directories: include_directories('.'),
    dependencies: [grpcpp_dep, protobuf_dep],
)

yuzu_proto_dep = declare_dependency(
    link_with: yuzu_proto_lib,
    sources: gen_hdrs,
    include_directories: include_directories('.'),
    dependencies: [grpcpp_dep, protobuf_dep],
)