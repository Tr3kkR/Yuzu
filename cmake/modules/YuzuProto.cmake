# YuzuProto.cmake — helper to generate protobuf + gRPC sources from .proto files

include_guard(GLOBAL)

# yuzu_proto_library(
#   NAME     <target-name>
#   PROTOS   <file.proto> ...
# )
function(yuzu_proto_library)
  cmake_parse_arguments(ARG "" "NAME" "PROTOS" ${ARGN})

  find_program(PROTOC_EXE       protoc        REQUIRED)
  find_program(GRPC_CPP_PLUGIN  grpc_cpp_plugin REQUIRED)

  set(PROTO_OUT "${CMAKE_BINARY_DIR}/generated/proto")
  file(MAKE_DIRECTORY "${PROTO_OUT}")

  set(GENERATED_SRCS "")
  set(GENERATED_HDRS "")

  foreach(PROTO_FILE IN LISTS ARG_PROTOS)
    get_filename_component(PROTO_NAME_WE "${PROTO_FILE}" NAME_WE)
    get_filename_component(PROTO_DIR    "${PROTO_FILE}" DIRECTORY)

    set(PB_H     "${PROTO_OUT}/${PROTO_NAME_WE}.pb.h")
    set(PB_CC    "${PROTO_OUT}/${PROTO_NAME_WE}.pb.cc")
    set(GRPC_H   "${PROTO_OUT}/${PROTO_NAME_WE}.grpc.pb.h")
    set(GRPC_CC  "${PROTO_OUT}/${PROTO_NAME_WE}.grpc.pb.cc")

    add_custom_command(
      OUTPUT  "${PB_H}" "${PB_CC}" "${GRPC_H}" "${GRPC_CC}"
      COMMAND "${PROTOC_EXE}"
        --cpp_out="${PROTO_OUT}"
        --grpc_out="${PROTO_OUT}"
        --plugin=protoc-gen-grpc="${GRPC_CPP_PLUGIN}"
        -I "${CMAKE_SOURCE_DIR}/proto"
        "${PROTO_FILE}"
      DEPENDS "${PROTO_FILE}"
      COMMENT "Generating protobuf/gRPC for ${PROTO_FILE}"
    )

    list(APPEND GENERATED_SRCS "${PB_CC}" "${GRPC_CC}")
    list(APPEND GENERATED_HDRS "${PB_H}"  "${GRPC_H}")
  endforeach()

  add_library(${ARG_NAME} STATIC ${GENERATED_SRCS} ${GENERATED_HDRS})
  target_include_directories(${ARG_NAME} PUBLIC "${PROTO_OUT}")
  target_link_libraries(${ARG_NAME} PUBLIC gRPC::grpc++ protobuf::libprotobuf)
endfunction()
