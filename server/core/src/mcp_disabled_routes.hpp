#pragma once

/// @file mcp_disabled_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-12, the Infra/Misc bundle) — the 3-route MCP-disabled
/// stub triple: `POST`/`GET`/`DELETE /mcp/v1/`, registered ONLY when
/// `cfg_.mcp_disable` is true (server.cpp keeps that conditional at the
/// call site; this module does not see or care about the flag). When MCP is
/// enabled, these three paths are instead served by the real `McpServer`
/// registration (a much larger, unrelated surface, untouched by this PR).
///
/// The handler body is copied verbatim from server.cpp — a single stateless
/// lambda with no captures at all, reused across all three verbs, so this
/// module needs no `Deps` struct (there is nothing to inject: no session,
/// no store, no permission gate — the whole point of the stub is to answer
/// honestly that MCP is off, for ANY caller, unauthenticated or not).
///
/// Routes (3), all unconditional (no gate — MCP is uniformly unavailable
/// regardless of caller):
///   POST   /mcp/v1/
///   GET    /mcp/v1/
///   DELETE /mcp/v1/
///
/// C8/CH-7(c) (preserved verbatim): answers a proper JSON-RPC
/// `kMcpDisabled` error instead of a generic 404, and answers GET/DELETE
/// too (not just POST), so a Streamable HTTP probe against any of the three
/// verbs gets the same honest disabled error.

#include <httplib.h>

namespace yuzu::server {
class HttpRouteSink;
} // namespace yuzu::server

namespace yuzu::server::mcp_disabled {

/// Register all 3 MCP-disabled stub routes against `sink`. No deps — see
/// this file's header comment for why.
void register_mcp_disabled_routes(HttpRouteSink& sink);

} // namespace yuzu::server::mcp_disabled
