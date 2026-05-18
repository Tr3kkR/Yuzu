#pragma once

/// @file rest_a4_envelope.hpp
///
/// W5.1 — testable shape contract for the agentic-first JSON SSE channel
/// at `/api/v1/events` and the A4 error envelope it emits.
///
/// Lives in `yuzu::server::detail` rather than `rest_api_v1.cpp`'s
/// anonymous namespace so unit tests can link directly to the helpers
/// and assert the wire shapes — the handler itself uses
/// `set_chunked_content_provider`, which httplib stores opaquely and
/// is not externally invokable from a TestRouteSink dispatch.
///
/// Both helpers are pure: no I/O, no global state beyond the
/// process-monotonic counter in `make_correlation_id`.

#include "execution_event_bus.hpp"

#include <string>
#include <string_view>

namespace yuzu::server::detail {

/// Generate a per-request correlation id of the form `req-<hex-ms>-<hex-seq>`.
/// Combines wall-clock ms with a process-monotonic counter so values are
/// unique within a single server instance even if two requests fire in the
/// same millisecond. Suitable for grep-by-token across spdlog / audit
/// rows; not a UUID, not security-sensitive.
std::string make_correlation_id();

/// A4-compliant error envelope. Per `docs/agentic-first-principle.md` §A4,
/// every failure response includes `code`, `message`, `correlation_id`, an
/// optional `remediation` hint, and the standard `meta.api_version`.
/// `retry_after_ms` is reserved for backoff signalling — omitted here
/// because W5.1's error sites have no rate-limit context to share; future
/// callers add it via a new overload rather than passing a sentinel.
std::string error_json_a4(int code, std::string_view message, std::string_view correlation_id,
                          std::string_view remediation = {});

/// JSON envelope emitted as the SSE `data:` payload on `/api/v1/events`.
/// Per A3, every event carries `execution_id` and a deterministic step
/// name from the published taxonomy (`agent-transition`,
/// `execution-progress`, `execution-completed`).
///
/// `ev.data` is raw-embedded as `payload` — the ExecutionTracker
/// publishers already produce well-formed JSON objects, so re-parsing
/// would be wasted work. Empty `ev.data` becomes `null` so the envelope
/// stays a valid JSON object even for synthesized events that carry no
/// payload (heartbeats handled separately, not through this helper).
std::string make_event_envelope(std::string_view execution_id,
                                const yuzu::server::ExecutionEvent& ev);

} // namespace yuzu::server::detail
