/**
 * hardware_plugin.cpp — Hardware inventory plugin for Yuzu
 *
 * Actions:
 *   "manufacturer" — Returns the system manufacturer.
 *   "model"        — Returns the system model/product name.
 *   "bios"         — Returns BIOS/UEFI vendor, version, and release date.
 *   "processors"   — Lists installed CPUs with model, cores, threads, clock.
 *   "memory"       — Lists installed memory modules.
 *   "disks"        — Lists physical disk drives.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value   (for scalar actions)
 *   key|field1|field2|...  (for list actions)
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <map>
#include <sstream>
#include <string>
#include <string_view>

#if defined(__linux__)
#include <fstream>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

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

// ── subprocess helper (Linux / macOS) ──────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}
#endif

// ── Linux: read a single-line sysfs/dmi file ──────────────────────────────

#ifdef __linux__
std::string read_dmi_file(const char* path) {
    std::ifstream f(path);
    if (!f)
        return {};
    std::string line;
    std::getline(f, line);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
        line.pop_back();
    return line;
}
#endif

// ── Windows: WMI helper class ─────────────────────────────────────────────

#ifdef _WIN32
class WmiQuery {
public:
    WmiQuery() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
            return;
        com_init_ = true;

        hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                                  RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
        // S_OK or RPC_E_TOO_LATE are both acceptable
        if (FAILED(hr) && hr != RPC_E_TOO_LATE)
            return;

        IWbemLocator* loc = nullptr;
        hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                              reinterpret_cast<void**>(&loc));
        if (FAILED(hr))
            return;
        locator_ = loc;

        IWbemServices* svc = nullptr;
        hr = locator_->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr, 0, nullptr,
                                     nullptr, &svc);
        if (FAILED(hr))
            return;
        services_ = svc;

        CoSetProxyBlanket(services_, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    }

    ~WmiQuery() {
        if (services_)
            services_->Release();
        if (locator_)
            locator_->Release();
        if (com_init_)
            CoUninitialize();
    }

    WmiQuery(const WmiQuery&) = delete;
    WmiQuery& operator=(const WmiQuery&) = delete;

    [[nodiscard]] bool valid() const { return services_ != nullptr; }

    // Execute a WQL query and call fn for each result object
    template <typename Fn> void query(const wchar_t* wql, Fn&& fn) {
        if (!services_)
            return;
        IEnumWbemClassObject* enumerator = nullptr;
        HRESULT hr = services_->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wql),
                                          WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                          nullptr, &enumerator);
        if (FAILED(hr) || !enumerator)
            return;

        IWbemClassObject* obj = nullptr;
        ULONG count = 0;
        while (enumerator->Next(WBEM_INFINITE, 1, &obj, &count) == S_OK) {
            fn(obj);
            obj->Release();
        }
        enumerator->Release();
    }

    // Get a string property from a WMI object
    static std::string get_string(IWbemClassObject* obj, const wchar_t* prop) {
        VARIANT vt;
        VariantInit(&vt);
        if (SUCCEEDED(obj->Get(prop, 0, &vt, nullptr, nullptr)) && vt.vt == VT_BSTR && vt.bstrVal) {
            int len = WideCharToMultiByte(CP_UTF8, 0, vt.bstrVal, -1, nullptr, 0, nullptr, nullptr);
            std::string result(len > 0 ? len - 1 : 0, '\0');
            if (len > 0) {
                WideCharToMultiByte(CP_UTF8, 0, vt.bstrVal, -1, result.data(), len, nullptr,
                                    nullptr);
            }
            VariantClear(&vt);
            return result;
        }
        VariantClear(&vt);
        return {};
    }

    // Get a uint32 property from a WMI object
    static uint32_t get_uint32(IWbemClassObject* obj, const wchar_t* prop) {
        VARIANT vt;
        VariantInit(&vt);
        uint32_t val = 0;
        if (SUCCEEDED(obj->Get(prop, 0, &vt, nullptr, nullptr))) {
            if (vt.vt == VT_I4 || vt.vt == VT_UI4)
                val = vt.ulVal;
        }
        VariantClear(&vt);
        return val;
    }

    // Get a uint64 property from a WMI object
    static uint64_t get_uint64(IWbemClassObject* obj, const wchar_t* prop) {
        VARIANT vt;
        VariantInit(&vt);
        uint64_t val = 0;
        if (SUCCEEDED(obj->Get(prop, 0, &vt, nullptr, nullptr))) {
            if (vt.vt == VT_BSTR && vt.bstrVal) {
                // WMI returns uint64 as string
                auto s = get_string(obj, prop);
                try {
                    val = std::stoull(s);
                } catch (...) {}
            } else if (vt.vt == VT_I4 || vt.vt == VT_UI4) {
                val = vt.ulVal;
            }
        }
        VariantClear(&vt);
        return val;
    }

private:
    bool com_init_ = false;
    IWbemLocator* locator_ = nullptr;
    IWbemServices* services_ = nullptr;
};
#endif

// ── manufacturer action ───────────────────────────────────────────────────

int do_manufacturer(yuzu::CommandContext& ctx) {
#ifdef __linux__
    auto mfr = read_dmi_file("/sys/class/dmi/id/sys_vendor");
    ctx.write_output(std::format("manufacturer|{}", mfr.empty() ? "unknown" : mfr));

#elif defined(__APPLE__)
    auto mfr = run_command("sysctl -n hw.manufacturer 2>/dev/null");
    // Apple hardware always says "Apple" but sysctl may not have this key
    ctx.write_output(std::format("manufacturer|{}", mfr.empty() ? "Apple Inc." : mfr));

#elif defined(_WIN32)
    WmiQuery wmi;
    std::string mfr;
    if (wmi.valid()) {
        wmi.query(L"SELECT Manufacturer FROM Win32_ComputerSystem",
                  [&](IWbemClassObject* obj) { mfr = WmiQuery::get_string(obj, L"Manufacturer"); });
    }
    ctx.write_output(std::format("manufacturer|{}", mfr.empty() ? "unknown" : mfr));

#else
    ctx.write_output("manufacturer|unknown");
#endif
    return 0;
}

// ── model action ──────────────────────────────────────────────────────────

int do_model(yuzu::CommandContext& ctx) {
#ifdef __linux__
    auto model = read_dmi_file("/sys/class/dmi/id/product_name");
    ctx.write_output(std::format("model|{}", model.empty() ? "unknown" : model));

#elif defined(__APPLE__)
    auto model = run_command("sysctl -n hw.model 2>/dev/null");
    ctx.write_output(std::format("model|{}", model.empty() ? "unknown" : model));

#elif defined(_WIN32)
    WmiQuery wmi;
    std::string model;
    if (wmi.valid()) {
        wmi.query(L"SELECT Model FROM Win32_ComputerSystem",
                  [&](IWbemClassObject* obj) { model = WmiQuery::get_string(obj, L"Model"); });
    }
    ctx.write_output(std::format("model|{}", model.empty() ? "unknown" : model));

#else
    ctx.write_output("model|unknown");
#endif
    return 0;
}

// ── bios action ───────────────────────────────────────────────────────────

int do_bios(yuzu::CommandContext& ctx) {
#ifdef __linux__
    auto vendor = read_dmi_file("/sys/class/dmi/id/bios_vendor");
    auto version = read_dmi_file("/sys/class/dmi/id/bios_version");
    auto date = read_dmi_file("/sys/class/dmi/id/bios_date");
    ctx.write_output(std::format("bios_vendor|{}", vendor.empty() ? "unknown" : vendor));
    ctx.write_output(std::format("bios_version|{}", version.empty() ? "unknown" : version));
    ctx.write_output(std::format("bios_date|{}", date.empty() ? "unknown" : date));

#elif defined(__APPLE__)
    // macOS doesn't expose traditional BIOS; report boot ROM version
    auto rom = run_command("system_profiler SPHardwareDataType 2>/dev/null | grep 'Boot ROM' | awk "
                           "-F': ' '{print $2}'");
    ctx.write_output("bios_vendor|Apple");
    ctx.write_output(std::format("bios_version|{}", rom.empty() ? "unknown" : rom));
    ctx.write_output("bios_date|N/A");

#elif defined(_WIN32)
    WmiQuery wmi;
    if (wmi.valid()) {
        wmi.query(
            L"SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS",
            [&](IWbemClassObject* obj) {
                auto vendor = WmiQuery::get_string(obj, L"Manufacturer");
                auto version = WmiQuery::get_string(obj, L"SMBIOSBIOSVersion");
                auto date = WmiQuery::get_string(obj, L"ReleaseDate");
                // WMI date format: "20240315000000.000000+000" → extract YYYY-MM-DD
                if (date.size() >= 8) {
                    date = date.substr(0, 4) + "-" + date.substr(4, 2) + "-" + date.substr(6, 2);
                }
                ctx.write_output(
                    std::format("bios_vendor|{}", vendor.empty() ? "unknown" : vendor));
                ctx.write_output(
                    std::format("bios_version|{}", version.empty() ? "unknown" : version));
                ctx.write_output(std::format("bios_date|{}", date.empty() ? "unknown" : date));
            });
    } else {
        ctx.write_output("bios_vendor|unknown");
        ctx.write_output("bios_version|unknown");
        ctx.write_output("bios_date|unknown");
    }

#else
    ctx.write_output("bios_vendor|unknown");
    ctx.write_output("bios_version|unknown");
    ctx.write_output("bios_date|unknown");
#endif
    return 0;
}

// ── processors action ─────────────────────────────────────────────────────

int do_processors(yuzu::CommandContext& ctx) {
#ifdef __linux__
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (!cpuinfo) {
        ctx.write_output("cpu|0|unknown|0|0|0");
        return 0;
    }
    // Collect unique physical CPUs
    struct CpuInfo {
        std::string model;
        int cores = 0;
        int threads = 0;
        double mhz = 0.0;
    };
    std::map<int, CpuInfo> cpus; // keyed by physical id
    int current_phys_id = 0;
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.starts_with("physical id")) {
            auto pos = line.find(':');
            if (pos != std::string::npos)
                current_phys_id = std::stoi(line.substr(pos + 1));
        } else if (line.starts_with("model name")) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                auto val = line.substr(pos + 2);
                cpus[current_phys_id].model = val;
            }
        } else if (line.starts_with("cpu cores")) {
            auto pos = line.find(':');
            if (pos != std::string::npos)
                cpus[current_phys_id].cores = std::stoi(line.substr(pos + 1));
        } else if (line.starts_with("siblings")) {
            auto pos = line.find(':');
            if (pos != std::string::npos)
                cpus[current_phys_id].threads = std::stoi(line.substr(pos + 1));
        } else if (line.starts_with("cpu MHz")) {
            auto pos = line.find(':');
            if (pos != std::string::npos)
                cpus[current_phys_id].mhz = std::stod(line.substr(pos + 1));
        }
    }
    if (cpus.empty()) {
        ctx.write_output("cpu|0|unknown|0|0|0");
    } else {
        for (auto& [id, c] : cpus) {
            ctx.write_output(
                std::format("cpu|{}|{}|{}|{}|{:.0f}", id, c.model, c.cores, c.threads, c.mhz));
        }
    }

#elif defined(__APPLE__)
    auto brand = run_command("sysctl -n machdep.cpu.brand_string 2>/dev/null");
    auto cores = run_command("sysctl -n hw.physicalcpu 2>/dev/null");
    auto threads = run_command("sysctl -n hw.logicalcpu 2>/dev/null");
    auto freq = run_command("sysctl -n hw.cpufrequency 2>/dev/null");
    double mhz = 0.0;
    if (!freq.empty()) {
        try {
            mhz = std::stod(freq) / 1e6;
        } catch (...) {}
    }
    ctx.write_output(std::format("cpu|0|{}|{}|{}|{:.0f}", brand.empty() ? "unknown" : brand,
                                 cores.empty() ? "0" : cores, threads.empty() ? "0" : threads,
                                 mhz));

#elif defined(_WIN32)
    WmiQuery wmi;
    if (wmi.valid()) {
        int idx = 0;
        wmi.query(L"SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM "
                  L"Win32_Processor",
                  [&](IWbemClassObject* obj) {
                      auto name = WmiQuery::get_string(obj, L"Name");
                      auto cores = WmiQuery::get_uint32(obj, L"NumberOfCores");
                      auto threads = WmiQuery::get_uint32(obj, L"NumberOfLogicalProcessors");
                      auto mhz = WmiQuery::get_uint32(obj, L"MaxClockSpeed");
                      ctx.write_output(
                          std::format("cpu|{}|{}|{}|{}|{}", idx++, name, cores, threads, mhz));
                  });
    } else {
        ctx.write_output("cpu|0|unknown|0|0|0");
    }

#else
    ctx.write_output("cpu|0|unknown|0|0|0");
#endif
    return 0;
}

// ── memory action ─────────────────────────────────────────────────────────

int do_memory(yuzu::CommandContext& ctx) {
#ifdef __linux__
    // Try dmidecode first (needs root), fall back to /proc/meminfo
    auto dmi = run_command("dmidecode -t memory 2>/dev/null");
    if (!dmi.empty() && dmi.find("Size:") != std::string::npos) {
        // Parse dmidecode output for each "Memory Device" block
        std::istringstream ss(dmi);
        std::string line;
        std::string slot, size, type, speed;
        bool in_device = false;
        while (std::getline(ss, line)) {
            // Trim leading whitespace
            auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos)
                continue;
            line = line.substr(start);

            if (line == "Memory Device") {
                // Emit previous device if any
                if (in_device && !size.empty() && size != "No Module Installed") {
                    // Extract numeric size in MB
                    std::string size_mb = size;
                    auto sp = size.find(' ');
                    if (sp != std::string::npos)
                        size_mb = size.substr(0, sp);
                    // Extract numeric speed
                    std::string speed_mhz = speed;
                    sp = speed.find(' ');
                    if (sp != std::string::npos)
                        speed_mhz = speed.substr(0, sp);
                    ctx.write_output(
                        std::format("dimm|{}|{}|{}|{}", slot, size_mb, type, speed_mhz));
                }
                slot.clear();
                size.clear();
                type.clear();
                speed.clear();
                in_device = true;
            } else if (in_device) {
                if (line.starts_with("Locator:")) {
                    slot = line.substr(line.find(':') + 2);
                } else if (line.starts_with("Size:")) {
                    size = line.substr(line.find(':') + 2);
                } else if (line.starts_with("Type:") && !line.starts_with("Type Detail")) {
                    type = line.substr(line.find(':') + 2);
                } else if (line.starts_with("Speed:")) {
                    speed = line.substr(line.find(':') + 2);
                }
            }
        }
        // Emit last device
        if (in_device && !size.empty() && size != "No Module Installed") {
            std::string size_mb = size;
            auto sp = size.find(' ');
            if (sp != std::string::npos)
                size_mb = size.substr(0, sp);
            std::string speed_mhz = speed;
            sp = speed.find(' ');
            if (sp != std::string::npos)
                speed_mhz = speed.substr(0, sp);
            ctx.write_output(std::format("dimm|{}|{}|{}|{}", slot, size_mb, type, speed_mhz));
        }
    } else {
        // Fallback: just report total memory from /proc/meminfo
        std::ifstream meminfo("/proc/meminfo");
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.starts_with("MemTotal:")) {
                auto pos = line.find_first_of("0123456789");
                if (pos != std::string::npos) {
                    auto kb = std::stoull(line.substr(pos));
                    ctx.write_output(std::format("dimm|total|{}|unknown|0", kb / 1024));
                }
                break;
            }
        }
    }

#elif defined(__APPLE__)
    auto mem = run_command("sysctl -n hw.memsize 2>/dev/null");
    if (!mem.empty()) {
        try {
            auto bytes = std::stoull(mem);
            ctx.write_output(std::format("dimm|total|{}|unknown|0", bytes / (1024 * 1024)));
        } catch (...) {
            ctx.write_output("dimm|total|unknown|unknown|0");
        }
    } else {
        ctx.write_output("dimm|total|unknown|unknown|0");
    }

#elif defined(_WIN32)
    WmiQuery wmi;
    if (wmi.valid()) {
        wmi.query(L"SELECT DeviceLocator, Capacity, MemoryType, SMBIOSMemoryType, Speed FROM "
                  L"Win32_PhysicalMemory",
                  [&](IWbemClassObject* obj) {
                      auto slot = WmiQuery::get_string(obj, L"DeviceLocator");
                      auto capacity = WmiQuery::get_uint64(obj, L"Capacity");
                      auto speed = WmiQuery::get_uint32(obj, L"Speed");
                      auto smbios_type = WmiQuery::get_uint32(obj, L"SMBIOSMemoryType");
                      // SMBIOSMemoryType: 26=DDR4, 34=DDR5, 24=DDR3, 20=DDR2
                      const char* type_str = "unknown";
                      switch (smbios_type) {
                      case 20:
                          type_str = "DDR2";
                          break;
                      case 24:
                          type_str = "DDR3";
                          break;
                      case 26:
                          type_str = "DDR4";
                          break;
                      case 34:
                          type_str = "DDR5";
                          break;
                      }
                      auto size_mb = capacity / (1024 * 1024);
                      ctx.write_output(
                          std::format("dimm|{}|{}|{}|{}", slot, size_mb, type_str, speed));
                  });
    } else {
        ctx.write_output("dimm|unknown|0|unknown|0");
    }

#else
    ctx.write_output("dimm|unknown|0|unknown|0");
#endif
    return 0;
}

// ── disks action ──────────────────────────────────────────────────────────

int do_disks(yuzu::CommandContext& ctx) {
#ifdef __linux__
    auto lsblk = run_command("lsblk -dno NAME,SIZE,TYPE,MODEL,TRAN 2>/dev/null");
    if (!lsblk.empty()) {
        std::istringstream ss(lsblk);
        std::string line;
        int idx = 0;
        while (std::getline(ss, line)) {
            // Fields are whitespace-separated; MODEL may contain spaces
            // Use fixed-width parsing: NAME SIZE TYPE rest...
            std::istringstream ls(line);
            std::string name, size, type, model, tran;
            ls >> name >> size >> type;
            // Read remaining as model + transport
            std::string rest;
            std::getline(ls, rest);
            // Trim leading space
            auto start = rest.find_first_not_of(" \t");
            if (start != std::string::npos)
                rest = rest.substr(start);
            // Last token might be transport (sata, nvme, usb, etc.)
            auto last_space = rest.rfind(' ');
            if (last_space != std::string::npos) {
                tran = rest.substr(last_space + 1);
                model = rest.substr(0, last_space);
            } else {
                model = rest;
            }
            if (type == "disk") {
                ctx.write_output(std::format("disk|{}|{}|{}|{}|{}", idx++,
                                             model.empty() ? name : model, size, type,
                                             tran.empty() ? "unknown" : tran));
            }
        }
    } else {
        ctx.write_output("disk|0|unknown|0|unknown|unknown");
    }

#elif defined(__APPLE__)
    auto diskutil = run_command("diskutil list -plist 2>/dev/null");
    // Simpler approach: use system_profiler
    auto sp = run_command(
        "system_profiler SPStorageDataType SPNVMeDataType SPSerialATADataType 2>/dev/null"
        " | grep -E '(Medium Type|Capacity|Device Name|Model)'"
        " | head -20");
    if (!sp.empty()) {
        // Just output raw key-value pairs
        std::istringstream ss(sp);
        std::string line;
        int idx = 0;
        while (std::getline(ss, line)) {
            auto colon = line.find(':');
            if (colon != std::string::npos) {
                auto key = line.substr(0, colon);
                auto val = line.substr(colon + 1);
                // Trim
                auto ks = key.find_first_not_of(" \t");
                if (ks != std::string::npos)
                    key = key.substr(ks);
                auto vs = val.find_first_not_of(" \t");
                if (vs != std::string::npos)
                    val = val.substr(vs);
                ctx.write_output(std::format("disk|{}|{}|{}|disk|unknown", idx++, key, val));
            }
        }
    }
    if (sp.empty()) {
        ctx.write_output("disk|0|unknown|0|unknown|unknown");
    }

#elif defined(_WIN32)
    WmiQuery wmi;
    if (wmi.valid()) {
        wmi.query(L"SELECT Index, Model, Size, MediaType, InterfaceType FROM Win32_DiskDrive",
                  [&](IWbemClassObject* obj) {
                      auto idx = WmiQuery::get_uint32(obj, L"Index");
                      auto model = WmiQuery::get_string(obj, L"Model");
                      auto size = WmiQuery::get_uint64(obj, L"Size");
                      auto media = WmiQuery::get_string(obj, L"MediaType");
                      auto iface = WmiQuery::get_string(obj, L"InterfaceType");
                      auto size_gb = size / (1024ULL * 1024 * 1024);
                      // Simplify media type
                      std::string type_str = "unknown";
                      if (media.find("SSD") != std::string::npos ||
                          media.find("Solid") != std::string::npos) {
                          type_str = "SSD";
                      } else if (media.find("Fixed") != std::string::npos ||
                                 media.find("Hard") != std::string::npos) {
                          type_str = "HDD";
                      } else if (media.find("Removable") != std::string::npos) {
                          type_str = "Removable";
                      }
                      ctx.write_output(
                          std::format("disk|{}|{}|{}|{}|{}", idx, model, size_gb, type_str, iface));
                  });
    } else {
        ctx.write_output("disk|0|unknown|0|unknown|unknown");
    }

#else
    ctx.write_output("disk|0|unknown|0|unknown|unknown");
#endif
    return 0;
}

} // namespace

class HardwarePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "hardware"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports hardware inventory: manufacturer, model, BIOS, CPU, memory, disks";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"manufacturer", "model", "bios", "processors",
                                     "memory",       "disks", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "manufacturer")
            return do_manufacturer(ctx);
        if (action == "model")
            return do_model(ctx);
        if (action == "bios")
            return do_bios(ctx);
        if (action == "processors")
            return do_processors(ctx);
        if (action == "memory")
            return do_memory(ctx);
        if (action == "disks")
            return do_disks(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(HardwarePlugin)
