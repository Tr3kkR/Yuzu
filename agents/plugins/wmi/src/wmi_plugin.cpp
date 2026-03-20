/**
 * wmi_plugin.cpp — Windows Management Instrumentation plugin for Yuzu
 *
 * Actions:
 *   "query"        — Run a WQL SELECT query.
 *   "get_instance" — Get all properties of a WMI class.
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
#include <comdef.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#endif

namespace {

YuzuPluginContext* g_ctx = nullptr;

#ifdef _WIN32
std::wstring to_wide(std::string_view s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring ws(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), ws.data(), len);
    return ws;
}

std::string from_bstr(BSTR bs) {
    if (!bs) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, bs, -1, nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(sz), '\0');
    WideCharToMultiByte(CP_UTF8, 0, bs, -1, s.data(), sz, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

std::string variant_to_string(VARIANT& v) {
    switch (v.vt) {
        case VT_BSTR:  return from_bstr(v.bstrVal);
        case VT_I4:    return std::to_string(v.lVal);
        case VT_UI4:   return std::to_string(v.ulVal);
        case VT_I2:    return std::to_string(v.iVal);
        case VT_BOOL:  return v.boolVal ? "true" : "false";
        case VT_R8:    return std::format("{}", v.dblVal);
        case VT_NULL:  return "(null)";
        case VT_EMPTY: return "(empty)";
        default:       return std::format("(vt={})", v.vt);
    }
}

bool is_select_only(std::string_view wql) {
    // Only allow SELECT statements
    auto trimmed = wql;
    while (!trimmed.empty() && trimmed.front() == ' ') trimmed.remove_prefix(1);
    return trimmed.size() >= 6 &&
           (trimmed[0] == 'S' || trimmed[0] == 's') &&
           (trimmed[1] == 'E' || trimmed[1] == 'e') &&
           (trimmed[2] == 'L' || trimmed[2] == 'l') &&
           (trimmed[3] == 'E' || trimmed[3] == 'e') &&
           (trimmed[4] == 'C' || trimmed[4] == 'c') &&
           (trimmed[5] == 'T' || trimmed[5] == 't');
}

class ComInit {
public:
    ComInit() { hr_ = CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
    ~ComInit() { if (SUCCEEDED(hr_)) CoUninitialize(); }
    bool ok() const { return SUCCEEDED(hr_); }
private:
    HRESULT hr_;
};
#endif

} // namespace

class WmiPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "wmi"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Windows Management Instrumentation — WQL queries and instance enumeration";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"query", "get_instance", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override { g_ctx = ctx.raw(); return {}; }
    void shutdown(yuzu::PluginContext&) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
#ifndef _WIN32
        ctx.write_output("error|WMI not available on this platform");
        return 1;
#else
        if (action == "query")        return do_query(ctx, params);
        if (action == "get_instance") return do_get_instance(ctx, params);
        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
#endif
    }

#ifdef _WIN32
private:
    int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto wql = params.get("wql");
        if (wql.empty()) { ctx.write_output("error|missing required parameter: wql"); return 1; }
        if (!is_select_only(wql)) { ctx.write_output("error|only SELECT queries are allowed"); return 1; }

        auto ns = params.get("namespace");
        if (ns.empty()) ns = "root\\cimv2";

        ComInit com;
        if (!com.ok()) { ctx.write_output("error|COM initialization failed"); return 1; }

        IWbemLocator* locator = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<void**>(&locator));
        if (FAILED(hr)) { ctx.write_output("error|failed to create WbemLocator"); return 1; }

        IWbemServices* services = nullptr;
        auto wns = to_wide(ns);
        hr = locator->ConnectServer(_bstr_t(wns.c_str()), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
        locator->Release();
        if (FAILED(hr)) { ctx.write_output(std::format("error|failed to connect to namespace {}", ns)); return 1; }

        CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

        IEnumWbemClassObject* enumerator = nullptr;
        auto wwql = to_wide(wql);
        hr = services->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wwql.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator);
        if (FAILED(hr)) { services->Release(); ctx.write_output("error|query execution failed"); return 1; }

        IWbemClassObject* obj = nullptr;
        ULONG count = 0;
        int row = 0;
        while (enumerator->Next(WBEM_INFINITE, 1, &obj, &count) == S_OK && count > 0) {
            // Enumerate all properties of each result
            obj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY);
            BSTR prop_name = nullptr;
            VARIANT prop_val;
            while (obj->Next(0, &prop_name, &prop_val, nullptr, nullptr) == WBEM_S_NO_ERROR) {
                ctx.write_output(std::format("row{}|{}|{}", row, from_bstr(prop_name), variant_to_string(prop_val)));
                SysFreeString(prop_name);
                VariantClear(&prop_val);
            }
            obj->Release();
            ++row;
        }

        enumerator->Release();
        services->Release();
        ctx.write_output(std::format("rows|{}", row));
        return 0;
    }

    int do_get_instance(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto cls = params.get("class");
        if (cls.empty()) { ctx.write_output("error|missing required parameter: class"); return 1; }

        auto wql = std::format("SELECT * FROM {}", cls);
        // Reuse query logic with synthesized WQL
        yuzu::Params synth_params = params;
        // Directly call do_query with the synthesized WQL — but we need to pass the wql param
        // Instead, just execute the WQL directly
        auto ns = params.get("namespace");
        if (ns.empty()) ns = "root\\cimv2";

        ComInit com;
        if (!com.ok()) { ctx.write_output("error|COM initialization failed"); return 1; }

        IWbemLocator* locator = nullptr;
        CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<void**>(&locator));
        IWbemServices* services = nullptr;
        locator->ConnectServer(_bstr_t(to_wide(ns).c_str()), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
        locator->Release();
        CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

        IEnumWbemClassObject* enumerator = nullptr;
        services->ExecQuery(_bstr_t(L"WQL"), _bstr_t(to_wide(wql).c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator);

        IWbemClassObject* obj = nullptr;
        ULONG count = 0;
        // Get first instance only
        if (enumerator->Next(5000, 1, &obj, &count) == S_OK && count > 0) {
            obj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY);
            BSTR prop_name = nullptr;
            VARIANT prop_val;
            while (obj->Next(0, &prop_name, &prop_val, nullptr, nullptr) == WBEM_S_NO_ERROR) {
                ctx.write_output(std::format("property|{}|{}", from_bstr(prop_name), variant_to_string(prop_val)));
                SysFreeString(prop_name);
                VariantClear(&prop_val);
            }
            obj->Release();
        }

        enumerator->Release();
        services->Release();
        return 0;
    }
#endif
};

YUZU_PLUGIN_EXPORT(WmiPlugin)
