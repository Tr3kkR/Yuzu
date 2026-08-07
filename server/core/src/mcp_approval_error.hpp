#pragma once

#include "approval_manager.hpp"
#include "mcp_jsonrpc.hpp"

#include <concepts>
#include <string>
#include <string_view>

namespace yuzu::server::mcp {

/// One body for BOTH approval-store failure sites on the MCP recall path: the
/// ticket lookup (rung 1) and the consume (rung 2). They were written
/// separately at first and said different things about the same condition.
///
/// `ConsumeFailure::kStoreError` (and the equivalent `get_checked` failure at
/// rung 1) has producers that are TRANSIENT (a busy or erroring SQLite step,
/// which a retry clears) and producers that are PERMANENT for the life of the
/// process (the store never opened). Answering the permanent case with "retry
/// this call unchanged" is an unbounded loop, and every attempt also writes
/// an audit row, so a degraded approval store turns into an audit-write loop
/// on the substrate already failing to serve it.
///
/// `is_open()` is the discriminator: a null handle does not recover without
/// an operator restarting the server. It is SUFFICIENT for the permanent
/// case, not exhaustive: an OPEN handle whose reads fail permanently
/// (CORRUPT, NOTADB, READONLY, FULL) still takes the transient arm and is
/// told to retry forever. That gap needs `sqlite3_extended_errcode` carried
/// on `ConsumeError`, which is a separate change (#2786 PR 1c).
///
/// The transient arm carries a concrete `retry_after_ms` because invariant A5
/// requires a retry directive to be machine-readable rather than prose. The
/// permanent arm omits the argument, so `a4_error`'s default (-1) applies and
/// the envelope serialises `retry_after_ms` as JSON null, this file's own
/// encoding for "not retryable".
///
/// Lives in a header, not an anonymous namespace, because the branch it
/// replaces had ZERO test coverage in either direction: a governance reviewer
/// deleted the whole thing once and no assertion moved. Unreachable code is
/// untested code.
///
/// `a4_error` is passed in rather than called directly so the caller's
/// correlation-id minting and envelope shape stay in one place, and so a test
/// can observe the arguments without parsing JSON. The constraint below names
/// both call shapes `a4_error` actually has (three-argument and
/// four-argument with a `long` retry hint); a caller satisfying only one
/// arity fails at this declaration with a readable message instead of deep
/// inside template instantiation.
template <typename A4Error>
concept ApprovalA4Error =
    requires(A4Error a4_error, int code, std::string_view message,
             std::string_view remediation, long retry_after_ms) {
        { a4_error(code, message, remediation) } -> std::convertible_to<std::string>;
        { a4_error(code, message, remediation, retry_after_ms) } -> std::convertible_to<std::string>;
    };

template <ApprovalA4Error A4Error>
std::string approval_store_error_body(const ApprovalManager& mgr, const A4Error& a4_error) {
    if (!mgr.is_open())
        return a4_error(kInternalError, "approval store unavailable",
                        "this will NOT clear on retry, the approval was not consumed and does "
                        "not need re-requesting while the 7-day window holds. Escalate to an "
                        "operator");
    return a4_error(kInternalError, "approval store temporarily unavailable",
                    "retry this call unchanged, the approval was NOT consumed and remains "
                    "valid; do NOT request a fresh one. The 7-day approval window keeps "
                    "running during an outage: if it elapses the ticket expires and a new "
                    "approval is required",
                    5000);
}

} // namespace yuzu::server::mcp
