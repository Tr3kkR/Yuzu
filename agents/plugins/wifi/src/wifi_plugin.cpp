/**
 * wifi_plugin.cpp — WiFi network scanning plugin for Yuzu
 *
 * Actions:
 *   "list_networks" — Scans for visible WiFi networks and returns SSID,
 *                     signal strength, security type, channel, and BSSID.
 *   "connected"     — Reports the currently connected WiFi network info.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   key|field1|field2|...
 *
 * Platform implementations:
 *   Windows: WlanEnumInterfaces + WlanGetAvailableNetworkList / WlanQueryInterface
 *   Linux:   rung 1, bounded sd-bus to NetworkManager (org.freedesktop.
 *            NetworkManager) when built with libsystemd; ANY sd-bus failure
 *            falls through to rung 2, nmcli via the bounded argv runner; a
 *            missing/failing nmcli falls through to rung 3, a raw iw/iwlist
 *            (list_networks) or iwconfig (connected) text dump. No shell
 *            hop anywhere in this file (no shell interpreter is ever exec'd).
 *   macOS:   list_networks — airport -s / system_profiler via the bounded
 *            argv runner (legacy; airport gone in 14+; unchanged scan
 *            behaviour, only the acquisition mechanism was argv-ized).
 *            connected     — CoreWLAN (wifi_corewlan.mm), untouched by this
 *            migration.
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (plg-H1)

#include "wifi_parsers.hpp"

#include <format>
#include <string>
#include <string_view>
#include <vector>

#ifdef __APPLE__
#include "wifi_corewlan.hpp"  // CoreWLAN current-connection query (first .mm TU)
#endif

#if defined(__linux__) || defined(__APPLE__)
#include <chrono>
#include <optional>
#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure (ABI4 result seam)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (ADR-3002)
#endif

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
#include <cstdint>
#include <cstdlib> // free (sd_bus_get_property_string's malloc'd result)

#include <systemd/sd-bus.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <wlanapi.h>
#pragma comment(lib, "wlanapi.lib")
#endif

namespace {

// Row-safe wrapper for the free-text fields (SSID / security / BSSID / raw scan
// blobs) that come from tool output or an AP beacon. `wifi` is NOT a key|value
// plugin server-side, so an unescaped '|' shifts columns and a '\n' injects a
// row (plg-H1). Applied at every emission site below, all platforms.
inline std::string sof(std::string_view v) { return yuzu::util::safe_output_field(v); }

// ── argv runner helper (Linux / macOS) ──────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
// Per-call wall-clock bound for the scan/connection tools (nmcli/iw/iwlist/
// iwconfig/airport/system_profiler) -- matches the deadline the deleted
// run_command()/sh -c helper used.
constexpr std::chrono::seconds kWifiCmdDeadline{20};

/// Outcome of run_tool(): captured output PLUS the raw runner result, so a
/// caller can forward the latter through the ABI4 result seam
/// (yuzu::agent::forward_runner_failure) itself instead of this helper
/// deciding that on the caller's behalf. Mirrors users_plugin.cpp's
/// run_tool()/ToolOutcome exactly.
struct ToolOutcome {
    std::string output;
    yuzu::agent::SubprocessResult res;
};

/// Direct-argv replacement for the deleted run_command() shell-string hop:
/// the same bounded, fork-lock-covered runner, but exec'd straight to
/// argv[0] with no shell in between -- no shell-quoting/injection surface,
/// and the old `2>/dev/null` suffix is simply this call's default
/// merge_stderr=false. Strips trailing CR/LF exactly as run_command() did.
/// `max_lines` (0 = unlimited) replicates what used to be a `| head -N`
/// pipe stage.
ToolOutcome run_tool(std::vector<std::string> argv, std::size_t max_lines = 0) {
    if (argv.empty() || argv.front().empty()) {
        // A probe_tool_path miss (empty argv[0]): report the same shape
        // run_bounded_subprocess uses for its own runtime-reject
        // (tool_ran=false, termination_reason=spawn_error -- both already
        // SubprocessResult's default member values) without attempting an
        // OS call.
        return ToolOutcome{std::string{}, yuzu::agent::SubprocessResult{}};
    }
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = kWifiCmdDeadline,
                                             .max_lines = max_lines,
                                             .stop_after_max_lines = max_lines != 0});
    std::string output = res.output;
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) {
        output.pop_back();
    }
    return ToolOutcome{std::move(output), std::move(res)};
}
#endif // __linux__ || __APPLE__

// ── Linux: NetworkManager (rung 1, bounded sd-bus) ──────────────────────
//
// ══════════════════════════════════════════════════════════════════════
// D-BUS TYPE-SIGNATURE TABLE. Every sd_bus read below carries a one-line
// comment citing its row here.
//
// Verification status (do not weaken without re-doing the work):
//   * Rows 1-5 -- interface, member and wire shape confirmed by LIVE
//     introspection of NetworkManager 1.52.1 (`gdbus introspect` +
//     `Properties.Get` against a running NM). Row 4 was WRONG on first
//     write: ActiveAccessPoint was read on ...Device, which answers
//     org.freedesktop.DBus.Error.InvalidArgs ("No such property"); the
//     property lives only on ...Device.Wireless. Corrected here.
//   * Rows 6-11 (AccessPoint) are confirmed against NM's published
//     introspection XML, but NOT runtime-confirmed: the verification host
//     had no wireless device, so no AccessPoint object existed to query.
//     Ssid really is 'ay' (a byte array that may hold non-UTF-8 and
//     embedded NULs) and Strength really is 'y', not 'u' -- these are the
//     two rows most likely to be mis-copied. Linux CI is the first venue
//     that can execute them.
//
//  # | Call                | Interface                                   | Member           | Wire shape
//  --|---------------------|----------------------------------------------|------------------|---------------------------------
//  1 | method (not a prop) | org.freedesktop.NetworkManager                | GetDevices       | returns 'ao' directly (no variant)
//  2 | Properties.Get      | org.freedesktop.NetworkManager.Device         | DeviceType       | 'v' wrapping 'u' (WIFI == 2)
//  3 | Properties.Get      | org.freedesktop.NetworkManager.Device.Wireless| AccessPoints     | 'v' wrapping 'ao'
//  4 | Properties.Get      | org.freedesktop.NetworkManager.Device.Wireless| ActiveAccessPoint| 'v' wrapping 'o' ("/" == none)
//  5 | Properties.Get      | org.freedesktop.NetworkManager.Device         | Interface        | 'v' wrapping 's' (connected's col5 -- see deviation note in wifi_parsers.hpp)
//  6 | Properties.Get      | org.freedesktop.NetworkManager.AccessPoint    | Ssid             | 'v' wrapping 'ay' (BYTE ARRAY, never 's')
//  7 | Properties.Get      | org.freedesktop.NetworkManager.AccessPoint    | Strength         | 'v' wrapping 'y'
//  8 | Properties.Get      | org.freedesktop.NetworkManager.AccessPoint    | HwAddress        | 'v' wrapping 's'
//  9 | Properties.Get      | org.freedesktop.NetworkManager.AccessPoint    | Frequency        | 'v' wrapping 'u' (MHz)
// 10 | Properties.Get      | org.freedesktop.NetworkManager.AccessPoint    | WpaFlags         | 'v' wrapping 'u' (bitmask)
// 11 | Properties.Get      | org.freedesktop.NetworkManager.AccessPoint    | RsnFlags         | 'v' wrapping 'u' (bitmask)
//
// Cite: NetworkManager D-Bus API spec (networkmanager.dev/docs/api/latest/
// spec.html) + nm-dbus-interface.h's NMDeviceType/NM80211ApSecurityFlags
// enums. GetAllAccessPoints() is a documented alternative to row #3's
// AccessPoints property read; not used here, to keep every AP read going
// through the same Properties.Get shape (one fewer call shape to audit).
//
// FAILURE POLICY (distinct from the STRUCTURAL pattern below, which is
// copied from firewall_plugin.cpp's query_firewalld): this function follows
// device_identity_plugin.cpp's sssd_list_domains_via_sdbus discipline, not
// firewall's per-zone degrade-gracefully pattern -- ANY read in the
// sequence above failing (wrong signature, bus error, budget exhausted)
// aborts the WHOLE query_nm_* call and the caller falls through to nmcli.
// A single flaky AP does not get silently dropped from an otherwise-good
// scan; the whole D-Bus attempt is abandoned instead. This is the more
// conservative of the two precedents in this codebase, deliberately chosen
// for a leg that has never met a real NetworkManager (see the package
// report's open questions).
// ══════════════════════════════════════════════════════════════════════
#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)

// RAII guards, identical shape to firewall_plugin.cpp:343-375 (BusGuard/
// SdBusErrorGuard/SdBusMessageGuard) -- deleted copies so none of these can
// double-release the underlying sd-bus object.
struct BusGuard {
    sd_bus* bus = nullptr;
    ~BusGuard() {
        if (bus)
            sd_bus_flush_close_unref(bus);
    }
    BusGuard() = default;
    BusGuard(const BusGuard&) = delete;
    BusGuard& operator=(const BusGuard&) = delete;
};
struct SdBusErrorGuard {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    ~SdBusErrorGuard() { sd_bus_error_free(&err); }
    // A user-declared (even deleted) copy constructor suppresses the
    // implicitly-declared default constructor entirely -- without this,
    // `SdBusErrorGuard err;` below fails to compile. Same fix as
    // firewall_plugin.cpp's identical guard.
    SdBusErrorGuard() = default;
    SdBusErrorGuard(const SdBusErrorGuard&) = delete;
    SdBusErrorGuard& operator=(const SdBusErrorGuard&) = delete;
};
struct SdBusMessageGuard {
    sd_bus_message* m = nullptr;
    ~SdBusMessageGuard() {
        if (m)
            sd_bus_message_unref(m);
    }
    SdBusMessageGuard() = default;
    SdBusMessageGuard(const SdBusMessageGuard&) = delete;
    SdBusMessageGuard& operator=(const SdBusMessageGuard&) = delete;
};
struct CStrGuard {
    char* s = nullptr;
    ~CStrGuard() {
        if (s)
            free(s);
    }
    CStrGuard() = default;
    CStrGuard(const CStrGuard&) = delete;
    CStrGuard& operator=(const CStrGuard&) = delete;
};

constexpr const char* kNmDest = "org.freedesktop.NetworkManager";
constexpr const char* kNmManagerPath = "/org/freedesktop/NetworkManager";
constexpr const char* kNmManagerIface = "org.freedesktop.NetworkManager";
constexpr const char* kNmDeviceIface = "org.freedesktop.NetworkManager.Device";
constexpr const char* kNmWirelessIface = "org.freedesktop.NetworkManager.Device.Wireless";
constexpr const char* kNmApIface = "org.freedesktop.NetworkManager.AccessPoint";
constexpr std::uint32_t kNmDeviceTypeWifi = 2; // NMDeviceType.NM_DEVICE_TYPE_WIFI (nm-dbus-interface.h)

// Total sd-bus budget for the whole read, split across every sequential
// call below via arm_next_call()'s remaining-budget re-arm -- same
// re-arm-with-the-remainder shape as firewall_plugin.cpp's
// kSdBusTotalBudgetUs / guardian_state_reader.cpp's, so a wedged
// NetworkManager cannot hold this call for an unbounded multiple of the
// per-method timeout.
constexpr std::uint64_t kSdBusTotalBudgetUs = 5'000'000; // 5s

// Opens the system bus and arms the total budget; ok()==false means
// "unreachable" -> the caller falls through to nmcli. arm_next_call()
// re-arms the per-call timeout to whatever remains of the total budget,
// returning false (caller must abort) once it's exhausted.
class NmBusSession {
public:
    NmBusSession() {
        if (sd_bus_open_system(&bus_.bus) < 0 || !bus_.bus)
            return; // D-Bus unreachable -> honest fall-through, never fabricate
        t_start_ = std::chrono::steady_clock::now();
        sd_bus_set_method_call_timeout(bus_.bus, kSdBusTotalBudgetUs);
        ok_ = true;
    }
    bool ok() const { return ok_; }
    sd_bus* bus() const { return bus_.bus; }

    bool arm_next_call() {
        const auto elapsed_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - t_start_)
                .count());
        if (elapsed_us >= kSdBusTotalBudgetUs)
            return false;
        sd_bus_set_method_call_timeout(bus_.bus, kSdBusTotalBudgetUs - elapsed_us);
        return true;
    }

private:
    BusGuard bus_;
    std::chrono::steady_clock::time_point t_start_;
    bool ok_ = false;
};

// ── generic Properties.Get helpers -- each returns std::nullopt on ANY
// sd-bus error (wrong signature, bus error, property absent), never a
// fabricated zero-value. sd_bus_get_property() issues the Properties.Get
// call and demarshals the reply past the outer 'v' wrapper itself, so each
// helper only reads the CONTAINED type named in the table above.

std::optional<std::uint32_t> nm_get_u32(sd_bus* bus, const char* path, const char* iface,
                                        const char* member) {
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    if (sd_bus_get_property(bus, kNmDest, path, iface, member, &err.err, &reply.m, "u") < 0)
        return std::nullopt;
    std::uint32_t v = 0;
    if (sd_bus_message_read(reply.m, "u", &v) < 0)
        return std::nullopt;
    return v;
}

std::optional<std::uint8_t> nm_get_byte(sd_bus* bus, const char* path, const char* iface,
                                        const char* member) {
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    if (sd_bus_get_property(bus, kNmDest, path, iface, member, &err.err, &reply.m, "y") < 0)
        return std::nullopt;
    std::uint8_t v = 0;
    if (sd_bus_message_read(reply.m, "y", &v) < 0)
        return std::nullopt;
    return v;
}

std::optional<std::string> nm_get_string(sd_bus* bus, const char* path, const char* iface,
                                         const char* member) {
    SdBusErrorGuard err;
    CStrGuard s;
    if (sd_bus_get_property_string(bus, kNmDest, path, iface, member, &err.err, &s.s) < 0 || !s.s)
        return std::nullopt;
    return std::string{s.s};
}

std::optional<std::string> nm_get_object_path(sd_bus* bus, const char* path, const char* iface,
                                              const char* member) {
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    if (sd_bus_get_property(bus, kNmDest, path, iface, member, &err.err, &reply.m, "o") < 0)
        return std::nullopt;
    const char* p = nullptr;
    if (sd_bus_message_read(reply.m, "o", &p) < 0 || !p)
        return std::nullopt;
    return std::string{p};
}

std::optional<std::vector<std::string>> nm_get_object_path_array(sd_bus* bus, const char* path,
                                                                  const char* iface,
                                                                  const char* member) {
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    if (sd_bus_get_property(bus, kNmDest, path, iface, member, &err.err, &reply.m, "ao") < 0)
        return std::nullopt;
    if (sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_ARRAY, "o") < 0)
        return std::nullopt;
    std::vector<std::string> out;
    const char* p = nullptr;
    int rr;
    while ((rr = sd_bus_message_read(reply.m, "o", &p)) > 0) {
        if (p)
            out.emplace_back(p);
    }
    sd_bus_message_exit_container(reply.m);
    if (rr < 0)
        return std::nullopt; // malformed reply mid-array -- honest failure, never a partial list
    return out;
}

std::optional<std::vector<std::uint8_t>> nm_get_byte_array(sd_bus* bus, const char* path,
                                                            const char* iface, const char* member) {
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    if (sd_bus_get_property(bus, kNmDest, path, iface, member, &err.err, &reply.m, "ay") < 0)
        return std::nullopt;
    const void* ptr = nullptr;
    std::size_t n = 0;
    if (sd_bus_message_read_array(reply.m, 'y', &ptr, &n) < 0)
        return std::nullopt;
    // A zero-length 'ay' (a hidden AP's empty Ssid) can come back with
    // ptr == nullptr; nullptr + 0 is formally UB, so short-circuit it.
    if (!ptr || n == 0)
        return std::vector<std::uint8_t>{};
    const auto* bytes = static_cast<const std::uint8_t*>(ptr);
    return std::vector<std::uint8_t>(bytes, bytes + n);
}

// NM.GetDevices (method call, NOT Properties.Get -- see table row #1) ->
// 'ao' directly, no variant wrapper. Same array-of-object-paths read shape
// as device_identity_plugin.cpp's sssd_list_domains_via_sdbus.
std::optional<std::vector<std::string>> nm_call_get_devices(sd_bus* bus) {
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    if (sd_bus_call_method(bus, kNmDest, kNmManagerPath, kNmManagerIface, "GetDevices", &err.err,
                           &reply.m, "") < 0)
        return std::nullopt;
    if (sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_ARRAY, "o") < 0)
        return std::nullopt;
    std::vector<std::string> out;
    const char* p = nullptr;
    int rr;
    while ((rr = sd_bus_message_read(reply.m, "o", &p)) > 0) {
        if (p)
            out.emplace_back(p);
    }
    sd_bus_message_exit_container(reply.m);
    if (rr < 0)
        return std::nullopt;
    return out;
}

// Reads all six AccessPoint properties (table rows #6-#11) for one AP
// object path in a bounded batch. std::nullopt on the first read that
// fails or on budget exhaustion -- per the FAILURE POLICY note above the
// table, this aborts the WHOLE query, not just this one AP.
std::optional<yuzu::wifi::NmAccessPointProps> nm_read_ap(NmBusSession& session,
                                                         const std::string& ap_path) {
    if (!session.arm_next_call())
        return std::nullopt;
    auto ssid = nm_get_byte_array(session.bus(), ap_path.c_str(), kNmApIface, "Ssid"); // table #6
    if (!ssid)
        return std::nullopt;
    if (!session.arm_next_call())
        return std::nullopt;
    auto strength = nm_get_byte(session.bus(), ap_path.c_str(), kNmApIface, "Strength"); // table #7
    if (!strength)
        return std::nullopt;
    if (!session.arm_next_call())
        return std::nullopt;
    auto hw = nm_get_string(session.bus(), ap_path.c_str(), kNmApIface, "HwAddress"); // table #8
    if (!hw)
        return std::nullopt;
    if (!session.arm_next_call())
        return std::nullopt;
    auto freq = nm_get_u32(session.bus(), ap_path.c_str(), kNmApIface, "Frequency"); // table #9
    if (!freq)
        return std::nullopt;
    if (!session.arm_next_call())
        return std::nullopt;
    auto wpa = nm_get_u32(session.bus(), ap_path.c_str(), kNmApIface, "WpaFlags"); // table #10
    if (!wpa)
        return std::nullopt;
    if (!session.arm_next_call())
        return std::nullopt;
    auto rsn = nm_get_u32(session.bus(), ap_path.c_str(), kNmApIface, "RsnFlags"); // table #11
    if (!rsn)
        return std::nullopt;

    yuzu::wifi::NmAccessPointProps props;
    props.ssid_bytes = std::move(*ssid);
    props.strength = *strength;
    props.hw_address = std::move(*hw);
    props.frequency_mhz = *freq;
    props.wpa_flags = *wpa;
    props.rsn_flags = *rsn;
    return props;
}

struct NmListResult {
    bool reachable = false; // false -> caller falls through to nmcli, never "no wifi"
    std::vector<yuzu::wifi::WifiNetworkRow> rows;
};

NmListResult query_nm_list_networks() {
    NmListResult result;
    NmBusSession session;
    if (!session.ok())
        return result;

    if (!session.arm_next_call())
        return result;
    auto devices = nm_call_get_devices(session.bus()); // table #1
    if (!devices)
        return result;

    for (const auto& dev_path : *devices) {
        if (!session.arm_next_call())
            return result;
        auto dtype = nm_get_u32(session.bus(), dev_path.c_str(), kNmDeviceIface, "DeviceType"); // table #2
        if (!dtype)
            return result;
        if (*dtype != kNmDeviceTypeWifi)
            continue;

        if (!session.arm_next_call())
            return result;
        auto ap_paths = nm_get_object_path_array(session.bus(), dev_path.c_str(), kNmWirelessIface,
                                                  "AccessPoints"); // table #3
        if (!ap_paths)
            return result;

        for (const auto& ap_path : *ap_paths) {
            auto props = nm_read_ap(session, ap_path);
            if (!props)
                return result;
            result.rows.push_back(yuzu::wifi::nm_ap_to_row(*props));
        }
    }
    result.reachable = true; // walked every device without an sd-bus error
    return result;
}

struct NmConnectedResult {
    bool reachable = false; // false -> caller falls through to nmcli, never "no wifi"
    std::optional<yuzu::wifi::WifiConnectedRow> row; // nullopt + reachable -> genuinely not connected
};

NmConnectedResult query_nm_connected() {
    NmConnectedResult result;
    NmBusSession session;
    if (!session.ok())
        return result;

    if (!session.arm_next_call())
        return result;
    auto devices = nm_call_get_devices(session.bus()); // table #1
    if (!devices)
        return result;

    for (const auto& dev_path : *devices) {
        if (!session.arm_next_call())
            return result;
        auto dtype = nm_get_u32(session.bus(), dev_path.c_str(), kNmDeviceIface, "DeviceType"); // table #2
        if (!dtype)
            return result;
        if (*dtype != kNmDeviceTypeWifi)
            continue;

        if (!session.arm_next_call())
            return result;
        auto active_ap =
            nm_get_object_path(session.bus(), dev_path.c_str(), kNmWirelessIface,
                               "ActiveAccessPoint"); // table #4
        if (!active_ap)
            return result;
        if (*active_ap == "/" || active_ap->empty())
            continue; // this wifi device isn't associated -- check the next one

        auto props = nm_read_ap(session, *active_ap);
        if (!props)
            return result;

        if (!session.arm_next_call())
            return result;
        auto iface_name =
            nm_get_string(session.bus(), dev_path.c_str(), kNmDeviceIface, "Interface"); // table #5
        if (!iface_name)
            return result;

        result.reachable = true;
        result.row = yuzu::wifi::nm_ap_to_connected_row(*props, *iface_name);
        return result;
    }
    result.reachable = true; // walked every wifi device; none associated -> genuinely not connected
    return result;
}
#endif // __linux__ && YUZU_HAVE_LIBSYSTEMD

#ifdef _WIN32
// wide->UTF-8 conversion now via the shared win_str.hpp (#1681); from_wide is
// behaviour-identical to the old NUL-terminated wide_to_utf8 for valid input.
using yuzu::win::from_wide;

// Convert DOT11_AUTH_ALGORITHM to human-readable string
const char* auth_to_string(DOT11_AUTH_ALGORITHM auth) {
    switch (auth) {
    case DOT11_AUTH_ALGO_80211_OPEN:
        return "Open";
    case DOT11_AUTH_ALGO_80211_SHARED_KEY:
        return "WEP-Shared";
    case DOT11_AUTH_ALGO_WPA:
        return "WPA-Enterprise";
    case DOT11_AUTH_ALGO_WPA_PSK:
        return "WPA-PSK";
    case DOT11_AUTH_ALGO_WPA_NONE:
        return "WPA-None";
    case DOT11_AUTH_ALGO_RSNA:
        return "WPA2-Enterprise";
    case DOT11_AUTH_ALGO_RSNA_PSK:
        return "WPA2-PSK";
    default:
        return "Unknown";
    }
}

// Convert DOT11_BSS_TYPE to string
const char* bss_type_to_string(DOT11_BSS_TYPE bss) {
    switch (bss) {
    case dot11_BSS_type_infrastructure:
        return "Infrastructure";
    case dot11_BSS_type_independent:
        return "Ad-hoc";
    default:
        return "Unknown";
    }
}
#endif

// ── list_networks action ──────────────────────────────────────────────────

int do_list_networks(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    HANDLE client = nullptr;
    DWORD negotiated_version = 0;
    DWORD result = WlanOpenHandle(2, nullptr, &negotiated_version, &client);
    if (result != ERROR_SUCCESS) {
        ctx.write_output("wifi|error|Cannot open WLAN handle|0|0|none");
        return 1;
    }

    PWLAN_INTERFACE_INFO_LIST iface_list = nullptr;
    result = WlanEnumInterfaces(client, nullptr, &iface_list);
    if (result != ERROR_SUCCESS || !iface_list || iface_list->dwNumberOfItems == 0) {
        ctx.write_output("wifi|error|No wireless interfaces found|0|0|none");
        if (iface_list)
            WlanFreeMemory(iface_list);
        WlanCloseHandle(client, nullptr);
        return 0;
    }

    for (DWORD i = 0; i < iface_list->dwNumberOfItems; ++i) {
        auto& iface = iface_list->InterfaceInfo[i];

        PWLAN_AVAILABLE_NETWORK_LIST net_list = nullptr;
        result = WlanGetAvailableNetworkList(client, &iface.InterfaceGuid, 0, nullptr, &net_list);
        if (result != ERROR_SUCCESS || !net_list)
            continue;

        for (DWORD j = 0; j < net_list->dwNumberOfItems; ++j) {
            auto& net = net_list->Network[j];

            // Convert SSID (raw bytes) to string
            std::string ssid(reinterpret_cast<const char*>(net.dot11Ssid.ucSSID),
                             net.dot11Ssid.uSSIDLength);
            if (ssid.empty())
                ssid = "<hidden>";

            auto signal = net.wlanSignalQuality; // 0-100%
            auto security = auth_to_string(net.dot11DefaultAuthAlgorithm);
            auto bss_type = bss_type_to_string(net.dot11BssType);
            bool connected = (net.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED) != 0;

            ctx.write_output(std::format("wifi|{}|{}|{}|{}|{}", sof(ssid), signal, sof(security),
                                         sof(bss_type), connected ? "true" : "false"));
        }
        WlanFreeMemory(net_list);
    }

    WlanFreeMemory(iface_list);
    WlanCloseHandle(client, nullptr);

#elif defined(__linux__)
#if defined(YUZU_HAVE_LIBSYSTEMD)
    if (auto nm = query_nm_list_networks(); nm.reachable) {
        if (nm.rows.empty()) {
            // A confirmed, definitive answer from a reachable NetworkManager
            // (not the ambiguous "empty output" nmcli's own leg below has to
            // guess about) -- report it honestly rather than silently
            // emitting nothing.
            ctx.write_output("wifi|info|NetworkManager reachable via D-Bus; no Wi-Fi networks "
                             "currently visible|0|0|none");
        } else {
            for (auto& row : nm.rows) {
                ctx.write_output(std::format("wifi|{}|{}|{}|{}|{}", sof(row.ssid), sof(row.signal),
                                             sof(row.security), sof(row.channel), sof(row.bssid)));
            }
        }
        return 0;
    }
    // NetworkManager D-Bus unreachable, or any call in the sequence failed
    // -> fall through to the nmcli argv rung (D-Bus failure is never
    // "no wifi").
#endif
    bool status_forwarded = false;
    // sink: wifi/do_list_networks#1 -- nmcli device wifi list (rung 2 argv;
    // replaces the deleted sh -c pipeline)
    auto nmcli_path = yuzu::agent::probe_tool_path({"/usr/bin/nmcli", "/bin/nmcli"});
    auto nmcli_res =
        run_tool({nmcli_path, "-t", "-f", "SSID,SIGNAL,SECURITY,CHAN,BSSID", "device", "wifi", "list"});
    status_forwarded = yuzu::agent::forward_runner_failure(ctx, nmcli_res.res);
    if (!nmcli_res.output.empty()) {
        for (auto& row : yuzu::wifi::parse_nmcli_wifi_list(nmcli_res.output)) {
            ctx.write_output(std::format("wifi|{}|{}|{}|{}|{}", sof(row.ssid), sof(row.signal),
                                         sof(row.security), sof(row.channel), sof(row.bssid)));
        }
    } else {
        // sink: wifi/do_list_networks#2 -- iw dev (interface discovery for
        // the iwlist fallback)
        auto iw_path = yuzu::agent::probe_tool_path({"/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw"});
        auto iw_res = run_tool({iw_path, "dev"});
        if (!status_forwarded)
            status_forwarded = yuzu::agent::forward_runner_failure(ctx, iw_res.res);
        auto ifaces = yuzu::wifi::parse_iw_dev_interfaces(iw_res.output);
        if (!ifaces.empty()) {
            // sink: wifi/do_list_networks#3 -- iwlist <iface> scan
            // (per-interface raw scan text; one spawn per discovered iface)
            auto iwlist_path =
                yuzu::agent::probe_tool_path({"/usr/sbin/iwlist", "/sbin/iwlist", "/usr/bin/iwlist"});
            for (auto& iface : ifaces) {
                auto scan_res = run_tool({iwlist_path, iface, "scan"});
                if (!status_forwarded)
                    status_forwarded = yuzu::agent::forward_runner_failure(ctx, scan_res.res);
                auto filtered = yuzu::wifi::filter_iwlist_scan_lines(scan_res.output);
                if (!filtered.empty()) {
                    ctx.write_output(std::format("wifi|scan_output|{}", sof(filtered)));
                }
            }
        } else {
            ctx.write_output("wifi|error|No wireless tools available (nmcli/iw)|0|0|none");
        }
    }

#elif defined(__APPLE__)
    // macOS: the `airport` utility was removed in macOS 14 (Sonoma). Try
    // it first for older systems, then fall back to `system_profiler
    // SPAirPortDataType` which is available everywhere but requires
    // Location Services authorisation to return SSIDs. If neither
    // produces output we still return rc=0 with an info marker so the
    // dispatch test passes — the agent isn't broken, the host just
    // can't enumerate Wi-Fi without elevated privilege.
    bool status_forwarded = false;
    // sink: wifi/do_list_networks#4 -- airport -s (legacy scan; absent on
    // macOS 14+)
    auto airport_res = run_tool(
        {"/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
         "-s"});
    status_forwarded = yuzu::agent::forward_runner_failure(ctx, airport_res.res);
    if (!airport_res.output.empty()) {
        for (auto& row : yuzu::wifi::parse_airport_scan(airport_res.output)) {
            ctx.write_output(std::format("wifi|{}|{}|{}|{}|{}", sof(row.ssid), sof(row.signal),
                                         sof(row.security), sof(row.channel), sof(row.bssid)));
        }
    } else {
        // sink: wifi/do_list_networks#5 -- system_profiler SPAirPortDataType
        // (Location-Services-gated fallback)
        auto sp_res =
            run_tool({"/usr/sbin/system_profiler", "SPAirPortDataType", "-detailLevel", "basic"});
        if (!status_forwarded)
            status_forwarded = yuzu::agent::forward_runner_failure(ctx, sp_res.res);
        auto sp_rows = sp_res.output.empty() ? std::vector<yuzu::wifi::WifiNetworkRow>{}
                                             : yuzu::wifi::parse_system_profiler_wifi(sp_res.output);
        for (auto& row : sp_rows) {
            ctx.write_output(std::format("wifi|{}|{}|{}|{}|-", sof(row.ssid), sof(row.signal),
                                         sof(row.security), sof(row.channel)));
        }
        if (sp_rows.empty()) {
            ctx.write_output("wifi|info|wi-fi scan unavailable; airport removed in macOS 14+ "
                             "and system_profiler requires Location Services|0|0|none");
        }
    }
#endif
    return 0;
}

// ── connected action ──────────────────────────────────────────────────────

int do_connected(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    HANDLE client = nullptr;
    DWORD negotiated_version = 0;
    DWORD result = WlanOpenHandle(2, nullptr, &negotiated_version, &client);
    if (result != ERROR_SUCCESS) {
        ctx.write_output("connected|none|Not connected|0|none|none");
        return 0;
    }

    PWLAN_INTERFACE_INFO_LIST iface_list = nullptr;
    result = WlanEnumInterfaces(client, nullptr, &iface_list);
    if (result != ERROR_SUCCESS || !iface_list) {
        WlanCloseHandle(client, nullptr);
        ctx.write_output("connected|none|Not connected|0|none|none");
        return 0;
    }

    bool found = false;
    for (DWORD i = 0; i < iface_list->dwNumberOfItems; ++i) {
        auto& iface = iface_list->InterfaceInfo[i];
        if (iface.isState != wlan_interface_state_connected)
            continue;

        // Query connection attributes
        PWLAN_CONNECTION_ATTRIBUTES conn_attrs = nullptr;
        DWORD attr_size = 0;
        WLAN_OPCODE_VALUE_TYPE opcode_type;
        result = WlanQueryInterface(client, &iface.InterfaceGuid,
                                    wlan_intf_opcode_current_connection, nullptr, &attr_size,
                                    reinterpret_cast<PVOID*>(&conn_attrs), &opcode_type);
        if (result != ERROR_SUCCESS || !conn_attrs)
            continue;

        // Extract SSID
        std::string ssid(
            reinterpret_cast<const char*>(conn_attrs->wlanAssociationAttributes.dot11Ssid.ucSSID),
            conn_attrs->wlanAssociationAttributes.dot11Ssid.uSSIDLength);

        auto signal = conn_attrs->wlanAssociationAttributes.wlanSignalQuality;
        auto security = auth_to_string(conn_attrs->wlanSecurityAttributes.dot11AuthAlgorithm);

        // Format BSSID
        auto* bssid = conn_attrs->wlanAssociationAttributes.dot11Bssid;
        auto bssid_str = std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", bssid[0],
                                     bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

        auto iface_name = from_wide(iface.strInterfaceDescription);

        ctx.write_output(
            std::format("connected|{}|{}|{}|{}|{}", sof(ssid), signal, sof(security), bssid_str,
                        sof(iface_name)));
        found = true;

        WlanFreeMemory(conn_attrs);
    }

    if (!found) {
        ctx.write_output("connected|none|Not connected|0|none|none");
    }

    WlanFreeMemory(iface_list);
    WlanCloseHandle(client, nullptr);

#elif defined(__linux__)
#if defined(YUZU_HAVE_LIBSYSTEMD)
    if (auto nm = query_nm_connected(); nm.reachable) {
        if (nm.row) {
            auto& row = *nm.row;
            ctx.write_output(std::format("connected|{}|{}|{}|{}|{}", sof(row.ssid), sof(row.signal),
                                         sof(row.security), sof(row.bssid), sof(row.connection)));
        } else {
            ctx.write_output("connected|none|Not connected|0|none|none");
        }
        return 0;
    }
    // NetworkManager D-Bus unreachable, or any call in the sequence failed
    // -> fall through to the nmcli argv rung.
#endif
    bool status_forwarded = false;
    // sink: wifi/do_connected#1 -- nmcli device show (rung 2 argv fallback)
    auto nmcli_path = yuzu::agent::probe_tool_path({"/usr/bin/nmcli", "/bin/nmcli"});
    auto nmcli_res = run_tool({nmcli_path, "-t", "-f",
                               "GENERAL.CONNECTION,WIFI.SSID,WIFI.SIGNAL,WIFI.SECURITY,WIFI.BSSID",
                               "device", "show"},
                              /*max_lines=*/20);
    status_forwarded = yuzu::agent::forward_runner_failure(ctx, nmcli_res.res);
    auto parsed = yuzu::wifi::parse_nmcli_device_show(nmcli_res.output);
    if (parsed) {
        auto& row = *parsed;
        ctx.write_output(std::format("connected|{}|{}|{}|{}|{}", sof(row.ssid), sof(row.signal),
                                     sof(row.security), sof(row.bssid), sof(row.connection)));
    } else {
        // sink: wifi/do_connected#2 -- iwconfig (ESSID/Signal blob fallback)
        auto iwconfig_path =
            yuzu::agent::probe_tool_path({"/usr/sbin/iwconfig", "/sbin/iwconfig", "/usr/bin/iwconfig"});
        auto iwconfig_res = run_tool({iwconfig_path});
        if (!status_forwarded)
            status_forwarded = yuzu::agent::forward_runner_failure(ctx, iwconfig_res.res);
        auto filtered = yuzu::wifi::filter_iwconfig_essid_signal_lines(iwconfig_res.output);
        auto essid = yuzu::wifi::parse_iwconfig_essid_blob(filtered);
        if (essid) {
            ctx.write_output(std::format("connected|{}|0|unknown|-|-", sof(*essid)));
        } else {
            ctx.write_output("connected|none|Not connected|0|none|none");
        }
    }

#elif defined(__APPLE__)
    // CoreWLAN, not `airport -I`: the private airport binary was removed in
    // macOS 14 (Sonoma), so the old shell-out returned nothing and we always
    // reported "Not connected" even while associated. Fields stay in the
    // established macOS order: SSID | RSSI | Security | BSSID | Channel.
    //
    // Location Services (macOS 14+) withholds SSID/BSSID from a background
    // daemon, but the association, RSSI, channel and security are still
    // readable — so an authorised-withheld SSID becomes an honest
    // "<ssid-withheld>" marker on a real connection, never a false
    // "Not connected".
    // A fresh struct each call; corewlan_current_connection leaves it at its
    // default (associated == false → "Not connected") when there is no Wi-Fi
    // interface, so format_connected_record is the single output path.
    yuzu::wifi::WifiConnection conn;
    yuzu::wifi::corewlan_current_connection(conn);
    ctx.write_output(yuzu::wifi::format_connected_record(conn));
#endif
    return 0;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Windows is native WLAN API throughout (rung 1).
//
// Linux is now rung 1 for BOTH actions: a bounded sd-bus session to
// NetworkManager (org.freedesktop.NetworkManager), zero processes spawned
// when it succeeds. ANY sd-bus failure (no libsystemd at build time, no
// system bus, NetworkManager not running, a signature mismatch never
// verified against a live host) falls through to nmcli via the argv
// runner (rung 2), which itself falls through to a raw iw/iwlist text dump
// (list_networks) or an iwconfig ESSID/Signal blob (connected) when nmcli
// is absent -- the SAME governed-shell-free argv discipline used
// throughout this file now, replacing the single `run_command()` shell-
// string hop every Linux (and macOS) call used to share.
//
// macOS's list_networks scan path is CONSTRAINED, not unsupported: it
// really does run `airport -s` and then a `system_profiler
// SPAirPortDataType` fallback, now via the bounded argv runner directly
// (rung 2 -- no shell hop) rather than through a governed shell, and it
// really does parse results into `wifi|SSID|…` records. What it cannot
// promise is an ANSWER: `airport` was removed in macOS 14 (Sonoma) and the
// system_profiler fallback needs Location Services authorisation a
// background daemon may not hold, so on a modern, unauthorised host both
// legs yield nothing and the honest "wifi|info|…" sentinel is emitted.
// That is the definition of CONSTRAINED — a real mechanism with a named
// limitation — whereas UNSUPPORTED asserts the OS cannot supply the
// capability at all, which is false for macOS ≤13 and for any host where
// Location Services is granted. macOS connected instead ships via CoreWLAN
// (wifi_corewlan.mm), a native framework — rung 1 — though Location
// Services (macOS 14+) can withhold the SSID/BSSID from a background
// daemon. Untouched by this migration.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "list_networks",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "NetworkManager D-Bus (sd-bus)",
         "falls back to nmcli via the argv runner (rung 2), then a raw iw/iwlist text dump "
         "when nmcli is unavailable"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "airport -s / system_profiler via argv runner",
         "airport was removed in macOS 14 (Sonoma); the system_profiler "
         "SPAirPortDataType fallback needs Location Services authorisation a "
         "background daemon may lack, so an unauthorised modern host yields no "
         "networks and an honest wifi|info sentinel"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "WlanGetAvailableNetworkList", nullptr},
    },
    {
        /* .action      = */ "connected",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "NetworkManager D-Bus (sd-bus)",
         "falls back to nmcli via the argv runner (rung 2), then a raw iwconfig "
         "ESSID/Signal blob when nmcli reports no SSID"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "CoreWLAN",
         "Location Services (macOS 14+) may withhold SSID/BSSID from a background daemon"},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "WlanQueryInterface", nullptr},
    },
};

} // namespace

class WifiPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "wifi"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Scans visible WiFi networks and reports current connection status";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list_networks", "connected", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "list_networks")
            return do_list_networks(ctx);
        if (action == "connected")
            return do_connected(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(WifiPlugin)
