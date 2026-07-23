#pragma once

// Test-only accessors for the internal MCP dispatch/classification tables.
//
// These expose copies of translation-unit-private tables defined in
// mcp_server.cpp (kToolSecurity / kToolAnnotation / kWriteTools) so the
// annotation cross-check test — a separate TU — can assert the served hints
// without duplicating the maps. Relocated out of mcp_server.hpp (issue #2385)
// so the production header carries no test-only surface. Definitions live in
// mcp_server.cpp; only the unit test includes this header.

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::mcp {

// The (tool, securable, operation) dispatch rows from the internal kToolSecurity
// map, so the annotation cross-check test can assert readOnlyHint/destructiveHint
// against the dispatch class without duplicating the map.
struct ToolSecurityRow {
    std::string_view name;
    std::string_view securable;
    std::string_view operation;
};
std::vector<ToolSecurityRow> tool_security_rows_for_test();

// The names explicitly classified in the internal kToolAnnotation table, so the
// cross-check test can prove every tool is classified rather than relying on the
// generator's safe fallback.
std::vector<std::string_view> tool_annotation_names_for_test();

// The --mcp-read-only guard's write-tool set, so the cross-check test can bind it
// to the non-Read dispatch class (a mutating tool missing from kWriteTools would
// silently execute under read-only mode).
std::vector<std::string_view> write_tool_names_for_test();

// The served kTools[] names (#2383 — no accessor existed before; the earlier
// tests derived the served surface from a live tools/list call).
std::vector<std::string> tool_names_for_test();

// Three-way C8 dispatch classification (#2383) — mirrors the internal
// ToolSecurityClass enum in mcp_server.cpp (kept in lockstep by the wrapper's
// exhaustive switch; the enum itself stays TU-private with the tables it
// classifies).
enum class ToolClassForTest {
    kUnknown,               // → "Unknown tool" (kMethodNotFound)
    kKnownRegistered,       // → C7 / tier / approval as normal
    kKnownMissingSecurity,  // → deny fail-closed
};

// Runs the REAL dispatch classifier over synthetic tables, so the three-way
// split cannot silently regress while validator tests stay green. Owning
// strings, not views: synthetic inputs are built inline in the test and would
// dangle behind a view-based signature. Nothing is retained past the call.
ToolClassForTest classify_tool_for_test(const std::string& tool_name,
                                        const std::vector<std::string>& known_tools,
                                        const std::vector<std::string>& registered_tools);

// Owning-string (name, operation) row for synthetic validator input.
struct ToolSecurityRowOwned {
    std::string name;
    std::string operation;
};

// Runs the REAL ctor registration validator over synthetic tables — throws
// std::runtime_error naming every offender, exactly as McpServer() does.
void validate_tool_registration_for_test(const std::vector<std::string>& tool_names,
                                         const std::vector<ToolSecurityRowOwned>& security_rows,
                                         const std::vector<std::string>& write_tools);

} // namespace yuzu::server::mcp
