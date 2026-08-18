// wmi_bounded.hpp -- shared bounded WMI query/method-call helpers.
//
// Hoisted from agents/plugins/license_scan/src/licensing_wmi.{hpp,cpp}
// (roadmap C-8) — that header's own comment said it was "shaped for
// extraction... ZERO plugin-specific dependencies", anticipating this move.
//
// Two unbounded `enumerator->Next(WBEM_INFINITE, ...)` call sites exist
// elsewhere in the tree (hardware_plugin.cpp's file-private WmiQuery, and
// the wmi plugin) — this helper exists to stop that pattern propagating.
// NEVER call Next(WBEM_INFINITE, ...); always bound both the per-Next wait
// and the overall enumeration under BoundedQueryOptions.
//
// Windows-only by construction (#ifdef _WIN32); the header is empty
// elsewhere.

#ifndef YUZU_SHARED_WMI_BOUNDED_HPP
#define YUZU_SHARED_WMI_BOUNDED_HPP

#ifdef _WIN32

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::shared::wmi {

struct BoundedQueryOptions {
    uint32_t next_timeout_ms = 10000;          // per-Next() wait bound (each retry)
    size_t row_cap = 512;                      // stop and mark truncated past this many rows
    uint64_t enumeration_deadline_ms = 60000;  // whole-enumeration bound across all retries
};

/// One result row: non-system property name -> stringified value
/// (VT_NULL / VT_EMPTY properties are omitted).
using WmiRow = std::map<std::string, std::string>;

struct BoundedQueryResult {
    std::vector<WmiRow> rows;
    bool truncated = false;  // row_cap reached — enumeration did NOT complete
    // Stable error token when the call failed; absent on success. Never a
    // silent empty result on failure — see the token list below.
    //   com_init_failed | wbem_locator_failed | wmi_connect_failed_<hr> |
    //   wmi_query_failed_<hr> | wmi_next_timeout | wmi_deadline_exceeded |
    //   wmi_next_failed_<hr>
    std::optional<std::string> error;
};

/// Run a WQL SELECT against `wmi_namespace` with bounded connect + bounded
/// semisynchronous enumeration. Never blocks unbounded: a wedged provider
/// surfaces as `wmi_next_timeout` / `wmi_deadline_exceeded` after the
/// configured bounds instead of hanging the agent.
BoundedQueryResult run_bounded_wmi_query(const std::wstring& wmi_namespace, const std::wstring& wql,
                                         const BoundedQueryOptions& opts = {});

/// Call a WMI instance METHOD (not a property read) via ExecMethod, using
/// the same bounded-connect + semisynchronous-timeout shape as
/// run_bounded_wmi_query (IWbemCallResult::GetResultObject(timeout) on the
/// async ExecMethod path). `in_params` are set as BSTR (VT_BSTR) input
/// parameters on the method's in-signature instance. On success, `rows`
/// holds exactly one row: the method's out-parameters (including any
/// `ReturnValue`), stringified the same way as a query row.
BoundedQueryResult exec_object_method(const std::wstring& wmi_namespace,
                                      const std::wstring& object_path, const std::wstring& method,
                                      const std::map<std::wstring, std::wstring>& in_params,
                                      const BoundedQueryOptions& opts = {});

} // namespace yuzu::shared::wmi

#endif // _WIN32

#endif // YUZU_SHARED_WMI_BOUNDED_HPP
