/**
 * rdp_control_plugin.cpp — Remote Desktop (RDP) control plugin for Yuzu
 *
 * Actions:
 *   "set_state" — Enable or disable Remote Desktop (param: state=enable|disable).
 *   "status"    — Report current RDP posture (registry + firewall + service).
 *
 * Enable flips three switches; disable reverts the first two:
 *   1. HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
 *      (REG_DWORD: 0 = allow, 1 = deny)
 *   2. The "Remote Desktop" firewall rule group, addressed by its
 *      locale-independent indirect string "@FirewallAPI.dll,-28752" via
 *      INetFwPolicy2 (no netsh shell-out, no localized group names)
 *   3. TermService — started on enable, left running on disable (the
 *      registry + firewall gates block new connections)
 *
 * Error semantics: no rollback. Every step reports its own status row and
 * `overall|ok` only when all attempted steps succeeded. Callers (the
 * ServiceNow change-window job) must treat anything other than overall|ok
 * as "state not confirmed" and retry — especially on the disable path,
 * which is the security-relevant direction.
 *
 * Windows-only. Returns error on Linux/macOS.
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <netfw.h>
#include <oleauto.h> // SysAllocString / SysFreeString
#endif

namespace {

#ifdef _WIN32

constexpr const wchar_t* kTerminalServerKey = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
constexpr const wchar_t* kDenyValueName = L"fDenyTSConnections";
// Locale-independent indirect string for the built-in "Remote Desktop"
// firewall rule group (resolved by Windows from FirewallAPI.dll).
constexpr const wchar_t* kRdpFirewallGroup = L"@FirewallAPI.dll,-28752";

// Mirrored in tests/unit/test_new_plugins.cpp (validation-mirror pattern —
// keep the two copies in sync). Kept inside #ifdef _WIN32 because its only
// caller (do_set_state) is Windows-only; on Linux/macOS it would be an
// uncalled static function and trip -Wunused-function under warning_level=3.
bool is_valid_rdp_state(std::string_view state) {
    return state == "enable" || state == "disable";
}

class ComInit {
public:
    ComInit() { hr_ = CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
    ~ComInit() {
        if (SUCCEEDED(hr_)) CoUninitialize();
    }
    // Non-copyable: a copy would duplicate hr_ and both destructors would call
    // CoUninitialize (unbalanced). Parity with ScHandle below.
    ComInit(const ComInit&) = delete;
    ComInit& operator=(const ComInit&) = delete;
    bool ok() const { return SUCCEEDED(hr_); }

private:
    HRESULT hr_;
};

/// RAII owner for SC_HANDLE (service control manager / service handles).
class ScHandle {
public:
    explicit ScHandle(SC_HANDLE h) : h_(h) {}
    ~ScHandle() {
        if (h_) CloseServiceHandle(h_);
    }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    SC_HANDLE get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }

private:
    SC_HANDLE h_;
};

/// RAII owner for an HKEY (RegCloseKey on scope exit). `put()` yields the
/// out-param for RegCreateKeyExW/RegOpenKeyExW.
class RegKey {
public:
    RegKey() = default;
    ~RegKey() {
        if (h_) RegCloseKey(h_);
    }
    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;
    PHKEY put() { return &h_; }
    HKEY get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }

private:
    HKEY h_ = nullptr;
};

/// RAII owner for a COM interface pointer (Release on scope exit). `put()`
/// yields the out-param for CoCreateInstance.
template <class T>
class ComPtr {
public:
    ComPtr() = default;
    ~ComPtr() {
        if (p_) p_->Release();
    }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    T** put() { return &p_; }
    T* operator->() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }

private:
    T* p_ = nullptr;
};

/// RAII owner for a BSTR (SysFreeString on scope exit).
class BStr {
public:
    explicit BStr(const wchar_t* s) : b_(SysAllocString(s)) {}
    ~BStr() {
        if (b_) SysFreeString(b_);
    }
    BStr(const BStr&) = delete;
    BStr& operator=(const BStr&) = delete;
    BSTR get() const { return b_; }
    explicit operator bool() const { return b_ != nullptr; }

private:
    BSTR b_;
};

/// Write fDenyTSConnections. Returns ERROR_SUCCESS or the Win32 error.
LONG set_deny_ts_connections(DWORD deny) {
    RegKey key;
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kTerminalServerKey, 0, nullptr, 0, KEY_SET_VALUE,
                              nullptr, key.put(), nullptr);
    if (rc != ERROR_SUCCESS) return rc;
    return RegSetValueExW(key.get(), kDenyValueName, 0, REG_DWORD,
                          reinterpret_cast<const BYTE*>(&deny), sizeof(deny));
}

/// Read fDenyTSConnections. Returns ERROR_SUCCESS or the Win32 error.
LONG get_deny_ts_connections(DWORD& deny) {
    DWORD size = sizeof(deny);
    return RegGetValueW(HKEY_LOCAL_MACHINE, kTerminalServerKey, kDenyValueName, RRF_RT_REG_DWORD,
                        nullptr, &deny, &size);
}

/// Acquire INetFwPolicy2 into an owning ComPtr (only inside a live ComInit).
HRESULT get_fw_policy(ComPtr<INetFwPolicy2>& policy) {
    return CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                            __uuidof(INetFwPolicy2), reinterpret_cast<void**>(policy.put()));
}

/// Enable/disable the Remote Desktop rule group across all profiles.
HRESULT set_rdp_firewall_group(bool enable) {
    ComPtr<INetFwPolicy2> policy;
    HRESULT hr = get_fw_policy(policy);
    if (FAILED(hr)) return hr;
    BStr group{kRdpFirewallGroup};
    if (!group) return E_OUTOFMEMORY;
    return policy->EnableRuleGroup(NET_FW_PROFILE2_ALL, group.get(),
                                   enable ? VARIANT_TRUE : VARIANT_FALSE);
}

/// Query whether the Remote Desktop rule group is enabled (all profiles).
HRESULT get_rdp_firewall_group(bool& enabled) {
    ComPtr<INetFwPolicy2> policy;
    HRESULT hr = get_fw_policy(policy);
    if (FAILED(hr)) return hr;
    BStr group{kRdpFirewallGroup};
    if (!group) return E_OUTOFMEMORY;
    VARIANT_BOOL on = VARIANT_FALSE;
    hr = policy->IsRuleGroupEnabled(NET_FW_PROFILE2_ALL, group.get(), &on);
    enabled = (on != VARIANT_FALSE);
    return hr;
}

/// Query TermService state. Returns ERROR_SUCCESS or the Win32 error.
LONG get_term_service_state(DWORD& state) {
    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!scm) return static_cast<LONG>(GetLastError());
    ScHandle svc{OpenServiceW(scm.get(), L"TermService", SERVICE_QUERY_STATUS)};
    if (!svc) return static_cast<LONG>(GetLastError());
    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
        return static_cast<LONG>(GetLastError());
    }
    state = ssp.dwCurrentState;
    return ERROR_SUCCESS;
}

/// Start TermService if not already running. Returns ERROR_SUCCESS,
/// ERROR_SERVICE_ALREADY_RUNNING (treated as success by callers), or the
/// Win32 error.
LONG start_term_service() {
    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!scm) return static_cast<LONG>(GetLastError());
    ScHandle svc{
        OpenServiceW(scm.get(), L"TermService", SERVICE_START | SERVICE_QUERY_STATUS)};
    if (!svc) return static_cast<LONG>(GetLastError());
    if (StartServiceW(svc.get(), 0, nullptr)) return ERROR_SUCCESS;
    return static_cast<LONG>(GetLastError());
}

const char* service_state_name(DWORD state) {
    switch (state) {
        case SERVICE_RUNNING:          return "running";
        case SERVICE_START_PENDING:    return "start_pending";
        case SERVICE_STOPPED:          return "stopped";
        case SERVICE_STOP_PENDING:     return "stop_pending";
        case SERVICE_PAUSED:           return "paused";
        case SERVICE_PAUSE_PENDING:    return "pause_pending";
        case SERVICE_CONTINUE_PENDING: return "continue_pending";
        default:                       return "unknown";
    }
}

// Pure RDP verdict derivation, taking only the three gate outcomes as bools so
// it is unit-testable cross-platform (mirrored in test_new_plugins.cpp). Returns
// "on" only when every gate is READABLE and OPEN; "unknown" when any gate could
// not be read (never report "off" on missing data — a security-critical "is
// remote access open?" check must distinguish "confirmed closed" from "couldn't
// tell"); "off" when all gates are readable but at least one is closed.
// Kept inside #ifdef _WIN32 (its only caller, do_status, is Windows-only) to
// avoid -Wunused-function on Linux/macOS.
const char* derive_rdp_verdict(bool deny_known, bool deny_allows, bool fw_known,
                               bool fw_enabled, bool svc_known, bool svc_running) {
    if (!deny_known || !fw_known || !svc_known)
        return "unknown";
    return (deny_allows && fw_enabled && svc_running) ? "on" : "off";
}
#endif

} // namespace

class RdpControlPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "rdp_control"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Remote Desktop control — enable/disable RDP (registry + firewall + TermService)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"set_state", "status", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext&) override { return {}; }
    void shutdown(yuzu::PluginContext&) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
#ifndef _WIN32
        (void)params;
        ctx.write_output(std::format("error|rdp_control not available on this platform ({})",
                                     action));
        return 1;
#else
        if (action == "set_state") return do_set_state(ctx, params);
        if (action == "status")    return do_status(ctx);
        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
#endif
    }

#ifdef _WIN32
private:
    int do_set_state(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto state = params.get("state");
        if (!is_valid_rdp_state(state)) {
            ctx.write_output("error|invalid state (use enable or disable)");
            return 1;
        }
        const bool enable = (state == "enable");
        bool all_ok = true;

        // 1. Registry — fDenyTSConnections (0 = allow, 1 = deny).
        if (LONG rc = set_deny_ts_connections(enable ? 0 : 1); rc == ERROR_SUCCESS) {
            ctx.write_output("reg_status|ok");
        } else {
            // ERROR_ACCESS_DENIED (5) here means the agent is not elevated.
            ctx.write_output(std::format("reg_status|error:{}", rc));
            all_ok = false;
        }

        // 2. Firewall — the Remote Desktop rule group, all profiles.
        {
            ComInit com;
            if (!com.ok()) {
                ctx.write_output("firewall_status|error:com_init");
                all_ok = false;
            } else if (HRESULT hr = set_rdp_firewall_group(enable); SUCCEEDED(hr)) {
                ctx.write_output("firewall_status|ok");
            } else {
                ctx.write_output(
                    std::format("firewall_status|error:0x{:08x}", static_cast<uint32_t>(hr)));
                all_ok = false;
            }
        }

        // 3. Service — ensure TermService is running on enable; on disable the
        //    registry + firewall gates block new connections, so the service is
        //    deliberately left alone (and enforce-stopping security-adjacent
        //    services is the pattern the Guardian denylist exists to prevent).
        if (enable) {
            LONG rc = start_term_service();
            if (rc == ERROR_SUCCESS || rc == ERROR_SERVICE_ALREADY_RUNNING) {
                ctx.write_output("service_status|running");
            } else {
                ctx.write_output(std::format("service_status|error:{}", rc));
                all_ok = false;
            }
        } else {
            ctx.write_output("service_status|untouched");
        }

        ctx.write_output(std::format("overall|{}", all_ok ? "ok" : "error"));
        return all_ok ? 0 : 1;
    }

    int do_status(yuzu::CommandContext& ctx) {
        bool all_known = true;

        DWORD deny = 1;
        bool deny_known = false;
        if (LONG rc = get_deny_ts_connections(deny); rc == ERROR_SUCCESS) {
            deny_known = true;
            ctx.write_output(std::format("deny_ts_connections|{}", deny));
        } else {
            ctx.write_output(std::format("deny_ts_connections|error:{}", rc));
            all_known = false;
        }

        bool fw_enabled = false;
        bool fw_known = false;
        {
            ComInit com;
            if (!com.ok()) {
                ctx.write_output("firewall_group|error:com_init");
                all_known = false;
            } else if (HRESULT hr = get_rdp_firewall_group(fw_enabled); SUCCEEDED(hr)) {
                fw_known = true;
                ctx.write_output(
                    std::format("firewall_group|{}", fw_enabled ? "enabled" : "disabled"));
            } else {
                ctx.write_output(
                    std::format("firewall_group|error:0x{:08x}", static_cast<uint32_t>(hr)));
                all_known = false;
            }
        }

        DWORD svc_state = 0;
        bool svc_known = false;
        if (LONG rc = get_term_service_state(svc_state); rc == ERROR_SUCCESS) {
            svc_known = true;
            ctx.write_output(std::format("term_service|{}", service_state_name(svc_state)));
        } else {
            ctx.write_output(std::format("term_service|error:{}", rc));
            all_known = false;
        }

        // Derived verdict. "on" only when every gate is readable and open;
        // "unknown" when any gate could not be read (a caller filtering on the
        // rdp row alone must not read a failed read as "off"/safe); "off" when
        // all gates are readable but at least one is closed. The non-zero exit
        // code also flags any unreadable gate for callers keying on status.
        const char* verdict = derive_rdp_verdict(deny_known, deny == 0, fw_known, fw_enabled,
                                                 svc_known, svc_state == SERVICE_RUNNING);
        ctx.write_output(std::format("rdp|{}", verdict));
        return all_known ? 0 : 1;
    }
#endif
};

YUZU_PLUGIN_EXPORT(RdpControlPlugin)
