/**
 * registry_plugin.cpp — Windows Registry plugin for Yuzu
 *
 * Actions:
 *   "get_value"        — Read a registry value.
 *   "set_value"        — Write a registry value.
 *   "delete_value"     — Delete a registry value.
 *   "delete_key"       — Delete a registry key.
 *   "key_exists"       — Check if a key exists.
 *   "enumerate_keys"   — List subkeys.
 *   "enumerate_values" — List values in a key.
 *
 * Windows-only. Returns error on Linux/macOS.
 */

#include <yuzu/plugin.hpp>

#include <spdlog/spdlog.h>

#include <cctype>
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
#endif

namespace {

YuzuPluginContext* g_ctx = nullptr;

#ifdef _WIN32
HKEY parse_hive(std::string_view hive) {
    if (hive == "HKLM") return HKEY_LOCAL_MACHINE;
    if (hive == "HKCU") return HKEY_CURRENT_USER;
    if (hive == "HKCR") return HKEY_CLASSES_ROOT;
    if (hive == "HKU")  return HKEY_USERS;
    return nullptr;
}

std::wstring to_wide(std::string_view s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring ws(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), ws.data(), len);
    return ws;
}

std::string from_wide(const wchar_t* ws, int len = -1) {
    if (!ws) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws, len, nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(sz), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, len, s.data(), sz, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

std::string reg_type_name(DWORD type) {
    switch (type) {
        case REG_SZ:        return "REG_SZ";
        case REG_DWORD:     return "REG_DWORD";
        case REG_QWORD:     return "REG_QWORD";
        case REG_BINARY:    return "REG_BINARY";
        case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
        case REG_MULTI_SZ:  return "REG_MULTI_SZ";
        default:            return "REG_UNKNOWN";
    }
}
#endif

} // namespace

class RegistryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "registry"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Windows Registry — get, set, delete, enumerate keys and values";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"get_value", "set_value", "delete_value", "delete_key",
                                     "key_exists", "enumerate_keys", "enumerate_values",
                                     "get_user_value", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override { g_ctx = ctx.raw(); return {}; }
    void shutdown(yuzu::PluginContext&) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
#ifndef _WIN32
        ctx.write_output("error|registry not available on this platform");
        return 1;
#else
        if (action == "get_value")        return do_get_value(ctx, params);
        if (action == "set_value")        return do_set_value(ctx, params);
        if (action == "delete_value")     return do_delete_value(ctx, params);
        if (action == "delete_key")       return do_delete_key(ctx, params);
        if (action == "key_exists")       return do_key_exists(ctx, params);
        if (action == "enumerate_keys")   return do_enumerate_keys(ctx, params);
        if (action == "enumerate_values") return do_enumerate_values(ctx, params);
        if (action == "get_user_value")   return do_get_user_value(ctx, params);
        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
#endif
    }

#ifdef _WIN32
private:
    int do_get_value(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        auto val_name = params.get("name");

        HKEY opened = nullptr;
        if (RegOpenKeyExW(hkey, to_wide(key_path).c_str(), 0, KEY_READ, &opened) != ERROR_SUCCESS) {
            ctx.write_output("error|key not found");
            return 1;
        }

        DWORD type = 0, size = 0;
        auto wname = to_wide(val_name);
        RegQueryValueExW(opened, wname.c_str(), nullptr, &type, nullptr, &size);

        std::vector<BYTE> data(size);
        if (RegQueryValueExW(opened, wname.c_str(), nullptr, &type, data.data(), &size) != ERROR_SUCCESS) {
            RegCloseKey(opened);
            ctx.write_output("error|value not found");
            return 1;
        }
        RegCloseKey(opened);

        std::string value;
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            value = from_wide(reinterpret_cast<const wchar_t*>(data.data()), static_cast<int>(size / sizeof(wchar_t)));
        } else if (type == REG_DWORD && size >= 4) {
            value = std::to_string(*reinterpret_cast<const DWORD*>(data.data()));
        } else if (type == REG_QWORD && size >= 8) {
            value = std::to_string(*reinterpret_cast<const uint64_t*>(data.data()));
        } else {
            // Binary: hex encode
            for (DWORD i = 0; i < size; ++i) value += std::format("{:02x}", data[i]);
        }

        ctx.write_output(std::format("value|{}", value));
        ctx.write_output(std::format("type|{}", reg_type_name(type)));
        return 0;
    }

    int do_set_value(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        auto val_name = params.get("name");
        auto value = params.get("value");
        auto type_str = params.get("type");
        if (type_str.empty()) type_str = "REG_SZ";

        HKEY opened = nullptr;
        if (RegCreateKeyExW(hkey, to_wide(key_path).c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &opened, nullptr) != ERROR_SUCCESS) {
            ctx.write_output("error|failed to open/create key");
            return 1;
        }

        LONG result;
        auto wname = to_wide(val_name);
        if (type_str == "REG_DWORD") {
            DWORD dval = static_cast<DWORD>(std::stoul(std::string{value}));
            result = RegSetValueExW(opened, wname.c_str(), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dval), sizeof(dval));
        } else {
            auto wval = to_wide(value);
            result = RegSetValueExW(opened, wname.c_str(), 0, REG_SZ,
                                    reinterpret_cast<const BYTE*>(wval.c_str()), static_cast<DWORD>((wval.size() + 1) * sizeof(wchar_t)));
        }
        RegCloseKey(opened);

        if (result != ERROR_SUCCESS) { ctx.write_output("error|failed to set value"); return 1; }
        ctx.write_output("status|ok");
        return 0;
    }

    int do_delete_value(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        auto val_name = params.get("name");

        HKEY opened = nullptr;
        if (RegOpenKeyExW(hkey, to_wide(key_path).c_str(), 0, KEY_SET_VALUE, &opened) != ERROR_SUCCESS) {
            ctx.write_output("error|key not found"); return 1;
        }
        auto result = RegDeleteValueW(opened, to_wide(val_name).c_str());
        RegCloseKey(opened);

        if (result != ERROR_SUCCESS) { ctx.write_output("error|value not found"); return 1; }
        ctx.write_output("status|ok");
        return 0;
    }

    int do_delete_key(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        if (RegDeleteKeyW(hkey, to_wide(key_path).c_str()) != ERROR_SUCCESS) {
            ctx.write_output("error|failed to delete key"); return 1;
        }
        ctx.write_output("status|ok");
        return 0;
    }

    int do_key_exists(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        HKEY opened = nullptr;
        bool exists = RegOpenKeyExW(hkey, to_wide(key_path).c_str(), 0, KEY_READ, &opened) == ERROR_SUCCESS;
        if (opened) RegCloseKey(opened);
        ctx.write_output(std::format("exists|{}", exists ? "true" : "false"));
        return 0;
    }

    int do_enumerate_keys(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        HKEY opened = nullptr;
        if (RegOpenKeyExW(hkey, to_wide(key_path).c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &opened) != ERROR_SUCCESS) {
            ctx.write_output("error|key not found"); return 1;
        }
        wchar_t name[256];
        for (DWORD i = 0; ; ++i) {
            DWORD name_len = 256;
            if (RegEnumKeyExW(opened, i, name, &name_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            ctx.write_output(std::format("subkey|{}", from_wide(name, static_cast<int>(name_len))));
        }
        RegCloseKey(opened);
        return 0;
    }

    int do_enumerate_values(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        HKEY opened = nullptr;
        if (RegOpenKeyExW(hkey, to_wide(key_path).c_str(), 0, KEY_QUERY_VALUE, &opened) != ERROR_SUCCESS) {
            ctx.write_output("error|key not found"); return 1;
        }
        wchar_t name[256];
        for (DWORD i = 0; ; ++i) {
            DWORD name_len = 256, type = 0;
            if (RegEnumValueW(opened, i, name, &name_len, nullptr, &type, nullptr, nullptr) != ERROR_SUCCESS) break;
            ctx.write_output(std::format("value|{}|{}", from_wide(name, static_cast<int>(name_len)), reg_type_name(type)));
        }
        RegCloseKey(opened);
        return 0;
    }

    int do_get_user_value(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto username = params.get("username");
        auto key = params.get("key");
        auto val_name = params.get("name");
        if (username.empty() || key.empty()) {
            ctx.write_output("error|missing required parameters: username, key");
            return 1;
        }

        // Build the path to the user's NTUSER.DAT
        // Typical location: C:\Users\<username>\NTUSER.DAT
        std::string profile_path = std::format("C:\\Users\\{}\\NTUSER.DAT", username);

        // Use a unique temporary subkey name under HKEY_USERS for the loaded hive
        std::string mount_key = std::format("YUZU_TEMP_{}", username);
        auto wmount = to_wide(mount_key);

        // Attempt to load the user's registry hive
        // Requires SE_RESTORE_NAME and SE_BACKUP_NAME privileges
        LONG load_result = RegLoadKeyW(HKEY_USERS, wmount.c_str(), to_wide(profile_path).c_str());

        bool we_loaded = (load_result == ERROR_SUCCESS);
        if (load_result != ERROR_SUCCESS && load_result != ERROR_SHARING_VIOLATION) {
            // ERROR_SHARING_VIOLATION means the hive is already loaded (user is logged in)
            // Try reading from HKU\<SID> — for simplicity, try the mount key anyway
            // or fall back to profile list
            ctx.write_output(std::format("error|failed to load hive for user '{}' (error {})",
                                          username, load_result));
            return 1;
        }

        // Read the value from the loaded hive
        std::string full_key = mount_key + "\\" + std::string{key};
        HKEY opened = nullptr;
        if (RegOpenKeyExW(HKEY_USERS, to_wide(full_key).c_str(), 0, KEY_READ, &opened) != ERROR_SUCCESS) {
            if (we_loaded) RegUnLoadKeyW(HKEY_USERS, wmount.c_str());
            ctx.write_output("error|key not found in user hive");
            return 1;
        }

        DWORD type = 0, size = 0;
        auto wname = to_wide(val_name);
        RegQueryValueExW(opened, wname.c_str(), nullptr, &type, nullptr, &size);

        std::vector<BYTE> data(size);
        if (RegQueryValueExW(opened, wname.c_str(), nullptr, &type, data.data(), &size) != ERROR_SUCCESS) {
            RegCloseKey(opened);
            if (we_loaded) RegUnLoadKeyW(HKEY_USERS, wmount.c_str());
            ctx.write_output("error|value not found in user hive");
            return 1;
        }
        RegCloseKey(opened);

        // Unload the hive if we loaded it
        if (we_loaded) {
            RegUnLoadKeyW(HKEY_USERS, wmount.c_str());
        }

        std::string value;
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            value = from_wide(reinterpret_cast<const wchar_t*>(data.data()), static_cast<int>(size / sizeof(wchar_t)));
        } else if (type == REG_DWORD && size >= 4) {
            value = std::to_string(*reinterpret_cast<const DWORD*>(data.data()));
        } else if (type == REG_QWORD && size >= 8) {
            value = std::to_string(*reinterpret_cast<const uint64_t*>(data.data()));
        } else {
            for (DWORD i = 0; i < size; ++i) value += std::format("{:02x}", data[i]);
        }

        ctx.write_output(std::format("username|{}", username));
        ctx.write_output(std::format("value|{}", value));
        ctx.write_output(std::format("type|{}", reg_type_name(type)));
        return 0;
    }

    // L7: Log access to sensitive registry paths for audit trail
    static void audit_sensitive_path(std::string_view hive, std::string_view key_path) {
        // Normalize to uppercase for comparison
        std::string upper_key;
        upper_key.reserve(key_path.size());
        for (char c : key_path) {
            upper_key += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        // Check for sensitive paths
        if (hive == "HKLM") {
            if (upper_key.starts_with("SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN")) {
                spdlog::info("Registry: accessing sensitive path HKLM\\{}", key_path);
            } else if (upper_key.starts_with("SYSTEM\\CURRENTCONTROLSET\\SERVICES")) {
                spdlog::info("Registry: accessing sensitive path HKLM\\{}", key_path);
            }
        }
    }

    struct ParsedParams { HKEY hkey; std::string_view key_path; bool ok; };
    ParsedParams parse_params(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto hive = params.get("hive");
        auto key = params.get("key");
        if (hive.empty() || key.empty()) {
            ctx.write_output("error|missing required parameters: hive, key");
            return {nullptr, {}, false};
        }
        auto hkey = parse_hive(hive);
        if (!hkey) {
            ctx.write_output("error|invalid hive (use HKLM, HKCU, HKCR, or HKU)");
            return {nullptr, {}, false};
        }
        audit_sensitive_path(hive, key);
        return {hkey, key, true};
    }
#endif
};

YUZU_PLUGIN_EXPORT(RegistryPlugin)
