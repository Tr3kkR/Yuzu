// SPDX-License-Identifier: Apache-2.0
// Wire-stability assertion — backend-agnostic, always compiled into
// yuzu_transport.
//
// Per the FROZEN commitment in proto/yuzu/transport/framing/v1/transport.proto
// and transport.hpp, the C++ `enum class StatusCode` and the generated
// proto enum `yuzu::transport::framing::v1::StatusCode` share numeric
// values. Drift here = silent error-mapping break. This was historically
// asserted inside grpc_channel.cpp; moved to its own TU in #376 PR 3 so
// it is asserted exactly once regardless of which backend(s) are linked.

#include "transport.pb.h"  // proto StatusCode enum
#include "yuzu/transport/transport.hpp"

namespace {
namespace pb = ::yuzu::transport::framing::v1;
namespace yt = ::yuzu::transport;
static_assert(static_cast<int>(yt::StatusCode::Ok) == pb::STATUS_CODE_OK);
static_assert(static_cast<int>(yt::StatusCode::Cancelled) == pb::STATUS_CODE_CANCELLED);
static_assert(static_cast<int>(yt::StatusCode::Unknown) == pb::STATUS_CODE_UNKNOWN);
static_assert(static_cast<int>(yt::StatusCode::InvalidArgument) == pb::STATUS_CODE_INVALID_ARGUMENT);
static_assert(static_cast<int>(yt::StatusCode::DeadlineExceeded) == pb::STATUS_CODE_DEADLINE_EXCEEDED);
static_assert(static_cast<int>(yt::StatusCode::NotFound) == pb::STATUS_CODE_NOT_FOUND);
static_assert(static_cast<int>(yt::StatusCode::AlreadyExists) == pb::STATUS_CODE_ALREADY_EXISTS);
static_assert(static_cast<int>(yt::StatusCode::PermissionDenied) == pb::STATUS_CODE_PERMISSION_DENIED);
static_assert(static_cast<int>(yt::StatusCode::ResourceExhausted) == pb::STATUS_CODE_RESOURCE_EXHAUSTED);
static_assert(static_cast<int>(yt::StatusCode::FailedPrecondition) == pb::STATUS_CODE_FAILED_PRECONDITION);
static_assert(static_cast<int>(yt::StatusCode::Aborted) == pb::STATUS_CODE_ABORTED);
static_assert(static_cast<int>(yt::StatusCode::OutOfRange) == pb::STATUS_CODE_OUT_OF_RANGE);
static_assert(static_cast<int>(yt::StatusCode::Unimplemented) == pb::STATUS_CODE_UNIMPLEMENTED);
static_assert(static_cast<int>(yt::StatusCode::Internal) == pb::STATUS_CODE_INTERNAL);
static_assert(static_cast<int>(yt::StatusCode::Unavailable) == pb::STATUS_CODE_UNAVAILABLE);
static_assert(static_cast<int>(yt::StatusCode::DataLoss) == pb::STATUS_CODE_DATA_LOSS);
static_assert(static_cast<int>(yt::StatusCode::Unauthenticated) == pb::STATUS_CODE_UNAUTHENTICATED);
}  // anonymous namespace
