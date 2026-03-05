grpc_dep = dependency('gRPC', method: 'cmake', modules: ['gRPC::grpc++'])
protobuf_dep = dependency('Protobuf', method: 'cmake', modules: ['protobuf::libprotobuf'])

protoc = find_program('protoc', required: true)
grpc_cpp_plugin = find_program('grpc_cpp_plugin', required: true)

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
    dependencies: [grpc_dep, protobuf_dep],
)

yuzu_proto_dep = declare_dependency(
    link_with: yuzu_proto_lib,
    sources: gen_hdrs,
    include_directories: include_directories('.'),
    dependencies: [grpc_dep, protobuf_dep],
)