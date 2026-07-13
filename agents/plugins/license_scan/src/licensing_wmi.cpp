/**
 * licensing_wmi.cpp — bounded WMI enumerator implementation (roadmap C-8).
 * See licensing_wmi.hpp for the contract. No plugin-specific includes by
 * design — this file is shaped for extraction to agents/shared/.
 */

#ifdef _WIN32

#include "licensing_wmi.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <comdef.h>
#include <wbemidl.h>

#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace yuzu::license_scan::wmi {

namespace {

using yuzu::win::from_wide;
using yuzu::win::to_wide;

// RAII COM init (clone of the wmi_plugin ComInit shape).
class ComInit {
public:
    ComInit() { hr_ = CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
    ~ComInit() {
        if (SUCCEEDED(hr_))
            CoUninitialize();
    }
    ComInit(const ComInit&) = delete;
    ComInit& operator=(const ComInit&) = delete;
    [[nodiscard]] bool ok() const { return SUCCEEDED(hr_); }

private:
    HRESULT hr_;
};

template <typename T> struct ComReleaser {
    T* p;
    explicit ComReleaser(T* ptr) : p(ptr) {}
    ~ComReleaser() {
        if (p)
            p->Release();
    }
    ComReleaser(const ComReleaser&) = delete;
    ComReleaser& operator=(const ComReleaser&) = delete;
};

// RAII for the BSTR + VARIANT that IWbemClassObject::Next hands back — same
// contract as ComReleaser above: own the resource, free it on EVERY exit. The
// per-property body ALLOCATES (variant_to_string, from_wide, and WmiRow::emplace
// — WmiRow is a std::map, so an emplace allocates a node), so the old manual
// SysFreeString/VariantClear pair leaked both on a std::bad_alloc thrown
// mid-row.
struct BstrGuard {
    BSTR b = nullptr;
    BstrGuard() = default;
    ~BstrGuard() {
        if (b)
            SysFreeString(b);
    }
    BstrGuard(const BstrGuard&) = delete;
    BstrGuard& operator=(const BstrGuard&) = delete;
};

// VariantInit in the ctor is load-bearing: the destructor VariantClears
// unconditionally, so the VARIANT must be a valid VT_EMPTY even on the Next()
// call that FAILS and never writes it (the old code left it uninitialised).
struct VariantGuard {
    VARIANT v;
    VariantGuard() { VariantInit(&v); }
    ~VariantGuard() { VariantClear(&v); }
    VariantGuard(const VariantGuard&) = delete;
    VariantGuard& operator=(const VariantGuard&) = delete;
};

std::string hr_hex(HRESULT hr) {
    static constexpr char hexc[] = "0123456789abcdef";
    std::string out = "0x";
    for (int shift = 28; shift >= 0; shift -= 4)
        out += hexc[(static_cast<unsigned long>(hr) >> shift) & 0xF];
    return out;
}

std::string variant_to_string(const VARIANT& v) {
    switch (v.vt) {
    case VT_BSTR:
        return from_wide(v.bstrVal);
    case VT_I4:
        return std::to_string(v.lVal);
    case VT_UI4:
        return std::to_string(v.ulVal);
    case VT_I2:
        return std::to_string(v.iVal);
    case VT_UI1:
        return std::to_string(static_cast<unsigned>(v.bVal));
    case VT_BOOL:
        return v.boolVal ? "true" : "false";
    case VT_R8:
        return std::to_string(v.dblVal);
    default:
        return {}; // VT_NULL / VT_EMPTY / exotic types: omitted by caller
    }
}

} // namespace

BoundedQueryResult run_bounded_wmi_query(const std::string& wmi_namespace, const std::string& wql,
                                         const BoundedQueryOptions& opts) {
    BoundedQueryResult result;

    ComInit com;
    if (!com.ok()) {
        result.error = "com_init_failed";
        return result;
    }

    IWbemLocator* locator = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, reinterpret_cast<void**>(&locator));
    if (FAILED(hr) || !locator) {
        result.error = "wbem_locator_failed";
        return result;
    }
    ComReleaser locator_guard{locator};

    // Bounded connect: WBEM_FLAG_CONNECT_USE_MAX_WAIT caps ConnectServer
    // (per MSDN, ~2 min worst case) instead of the default indefinite wait —
    // ConnectServer exposes no finer timeout knob (C-8 connect bound).
    IWbemServices* services = nullptr;
    const std::wstring wns = to_wide(wmi_namespace);
    hr = locator->ConnectServer(_bstr_t(wns.c_str()), nullptr, nullptr, nullptr,
                                WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, &services);
    if (FAILED(hr) || !services) {
        result.error = "wmi_connect_failed_" + hr_hex(hr);
        return result;
    }
    ComReleaser services_guard{services};

    CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    // Semisynchronous enumeration (FORWARD_ONLY | RETURN_IMMEDIATELY) is what
    // makes the per-Next timeout real — a synchronous enumerator ignores it.
    IEnumWbemClassObject* enumerator = nullptr;
    const std::wstring wwql = to_wide(wql);
    hr = services->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wwql.c_str()),
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr,
                             &enumerator);
    if (FAILED(hr) || !enumerator) {
        result.error = "wmi_query_failed_" + hr_hex(hr);
        return result;
    }
    ComReleaser enumerator_guard{enumerator};

    const ULONGLONG start_ticks = GetTickCount64();
    while (true) {
        if (result.rows.size() >= opts.row_cap) {
            // C-8 row cap: stop reading. The enumeration did NOT complete, so
            // the caller must not treat this as a structurally-successful
            // probe (ADR-0024 D3) — rows are returned for diagnostics.
            result.truncated = true;
            break;
        }
        // Whole-enumeration deadline (C-8), checked UNCONDITIONALLY at the top of
        // every iteration. The WBEM_S_TIMEDOUT retry branch below only bounds a
        // Next() that STALLS; a misbehaving provider that dribbles rows just under
        // the per-Next timeout keeps returning WBEM_S_NO_ERROR and never trips
        // that branch — so without this check it could run unbounded. A partial
        // enumeration is not a structurally-successful probe (ADR-0024 D3): clear
        // the rows and fail with a reason distinct from the per-Next stall token.
        if (GetTickCount64() - start_ticks >=
            static_cast<ULONGLONG>(opts.enumeration_deadline_ms)) {
            result.error = "wmi_deadline_exceeded";
            result.rows.clear();
            return result;
        }
        IWbemClassObject* obj = nullptr;
        ULONG count = 0;
        hr = enumerator->Next(opts.next_timeout_ms, 1, &obj, &count);
        if (hr == WBEM_S_FALSE && count == 0)
            break; // enumeration complete
        if (hr == WBEM_S_TIMEDOUT) {
            // Semisynchronous Next: WBEM_S_TIMEDOUT means "no object ready
            // yet — still working", not "wedged" (a cold SLP provider takes
            // ~15 s to yield its first row). Retry, but only while inside
            // the overall enumeration deadline — C-8's fail-with-reason
            // bound on a genuinely wedged provider.
            const ULONGLONG elapsed = GetTickCount64() - start_ticks;
            if (elapsed >= static_cast<ULONGLONG>(opts.enumeration_deadline_ms)) {
                result.error = "wmi_next_timeout";
                result.rows.clear();
                return result;
            }
            continue;
        }
        if (FAILED(hr) || count == 0 || !obj) {
            result.error = "wmi_next_failed_" + hr_hex(hr);
            result.rows.clear();
            return result;
        }
        ComReleaser obj_guard{obj};

        WmiRow row;
        obj->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY);
        while (true) {
            // Guards are scoped PER ITERATION: Next() overwrites both out-params
            // each time, so ownership binds to the row-property body that
            // allocates. EndEnumeration is skipped on an exceptional unwind, but
            // obj_guard releases the object immediately after, taking the
            // enumeration state with it.
            BstrGuard prop_name;
            VariantGuard prop_val;
            if (obj->Next(0, &prop_name.b, &prop_val.v, nullptr, nullptr) != WBEM_S_NO_ERROR)
                break;
            std::string value = variant_to_string(prop_val.v);
            if (!value.empty())
                row.emplace(from_wide(prop_name.b), std::move(value));
        }
        obj->EndEnumeration();
        result.rows.push_back(std::move(row));
    }

    result.ok = true;
    return result;
}

BoundedQueryResult query_software_licensing_products(const BoundedQueryOptions& opts) {
    // SELECT * — see the header for why a named-property list would break on
    // Windows builds whose SLP class lacks newer properties.
    return run_bounded_wmi_query("root\\cimv2", "SELECT * FROM SoftwareLicensingProduct", opts);
}

} // namespace yuzu::license_scan::wmi

#endif // _WIN32
