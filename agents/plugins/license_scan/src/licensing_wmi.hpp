/**
 * licensing_wmi.hpp — bounded WMI enumerator (roadmap C-8) + the
 * SoftwareLicensingProduct query for the license_scan plugin.
 *
 * C-8: this is the FIRST bounded WMI enumerator in the codebase — both
 * existing consumers (wmi_plugin.cpp:181, hardware_plugin.cpp:151) spin on
 * `WBEM_INFINITE` (latent agent-hang risk, tracked as issue I-4). Bounds:
 *   - bounded connect (WBEM_FLAG_CONNECT_USE_MAX_WAIT — the WMI-sanctioned
 *     connect bound; ConnectServer has no millisecond knob),
 *   - 10 s per-`Next` timeout (semisynchronous enumeration), retried under
 *     an overall enumeration deadline (see BoundedQueryOptions — a
 *     WBEM_S_TIMEDOUT is "still working", not "wedged"),
 *   - 512-row cap,
 *   - fail-with-reason (stable reason tokens, never a silent empty result).
 *
 * Deliberately plugin-local but shaped for extraction (C-8): the enumerator
 * has ZERO plugin-specific dependencies — no licensing_record.hpp, no
 * licensing_parsers.hpp, just std + COM/WMI — so a follow-up can lift it to
 * agents/shared/ and migrate the two legacy consumers without untangling
 * anything.
 *
 * Windows-only by construction (the plugin's other TUs never touch WMI).
 */

#ifndef YUZU_LICENSE_SCAN_LICENSING_WMI_HPP
#define YUZU_LICENSE_SCAN_LICENSING_WMI_HPP

#ifdef _WIN32

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace yuzu::license_scan::wmi {

struct BoundedQueryOptions {
    long next_timeout_ms = 10'000;  // C-8: 10 s per-Next timeout (each wait)
    std::size_t row_cap = 512;      // C-8: 512-row cap
    // Overall enumeration deadline. WBEM_S_TIMEDOUT from a semisynchronous
    // Next() means "no object ready yet — still working", NOT "wedged", so a
    // single 10 s wait must be retried while the provider makes progress
    // (measured on real hardware: a cold SoftwareLicensingProduct enumeration
    // takes ~15 s for the first row while sppsvc spins up). Each wait stays
    // bounded at next_timeout_ms; this deadline bounds the WHOLE enumeration
    // so retries cannot become the unbounded hang C-8 exists to prevent.
    long long enumeration_deadline_ms = 60'000;
};

/// One result row: non-system property name → stringified value
/// (VT_NULL / VT_EMPTY properties are omitted).
using WmiRow = std::map<std::string, std::string>;

struct BoundedQueryResult {
    bool ok = false;
    bool truncated = false;  // row_cap reached — enumeration did NOT complete
    std::string error;       // reason token when !ok: com_init_failed |
                             // wbem_locator_failed | wmi_connect_failed_<hr> |
                             // wmi_query_failed_<hr> | wmi_next_timeout |
                             // wmi_next_failed_<hr>
    std::vector<WmiRow> rows;
};

/// Run a WQL SELECT against `wmi_namespace` with the C-8 bounds. Never blocks
/// unbounded: a wedged provider surfaces as `wmi_next_timeout` after
/// next_timeout_ms instead of hanging the agent.
BoundedQueryResult run_bounded_wmi_query(const std::string& wmi_namespace, const std::string& wql,
                                         const BoundedQueryOptions& opts = {});

/// The SLP query (roadmap surface table Windows row 1): all
/// SoftwareLicensingProduct instances from root\cimv2. SELECT * rather than a
/// property list because the property set drifts across Windows versions
/// (e.g. ProductKeyChannel is absent on older builds and a named-property
/// query would fail outright); the caller reads Name, Description,
/// LicenseStatus, GracePeriodRemaining, PartialProductKey, ProductKeyChannel
/// and EvaluationEndDate from the row map and filters to rows with a
/// PartialProductKey or a meaningful (non-zero) LicenseStatus.
BoundedQueryResult query_software_licensing_products(const BoundedQueryOptions& opts = {});

} // namespace yuzu::license_scan::wmi

#endif // _WIN32

#endif // YUZU_LICENSE_SCAN_LICENSING_WMI_HPP
