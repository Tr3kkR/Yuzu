/**
 * yuzu/plugin.hpp — Ergonomic C++23 wrapper around the C plugin ABI
 *
 * Use this header when writing plugins in C++. It provides:
 *
 *   - yuzu::Plugin   — CRTP base class for plugins
 *   - yuzu::Context  — RAII wrapper around YuzuCommandContext
 *   - YUZU_PLUGIN_EXPORT(ClassName)  — generates the required C export
 *
 * The C ABI (plugin.h) is still what the agent loads; this header just makes
 * it nicer to implement from C++.
 */

#pragma once

#include "plugin.h"

#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace yuzu {

// ── Error type ────────────────────────────────────────────────────────────────

struct PluginError {
    int         code;
    std::string message;
};

template <typename T>
using Result = std::expected<T, PluginError>;

// ── Parameter access ──────────────────────────────────────────────────────────

class Params {
public:
    explicit Params(std::span<const YuzuParam> raw) noexcept : raw_{raw} {}

    [[nodiscard]] std::string_view get(std::string_view key,
                                       std::string_view def = {}) const noexcept {
        for (const auto& p : raw_) {
            if (p.key && key == p.key) return p.value ? p.value : def;
        }
        return def;
    }

    [[nodiscard]] bool has(std::string_view key) const noexcept {
        for (const auto& p : raw_) {
            if (p.key && key == p.key) return true;
        }
        return false;
    }

private:
    std::span<const YuzuParam> raw_;
};

// ── Command context wrapper ───────────────────────────────────────────────────

class CommandContext {
public:
    explicit CommandContext(YuzuCommandContext* raw) noexcept : raw_{raw} {}

    void write_output(std::string_view text) {
        yuzu_ctx_write_output(raw_, std::string{text}.c_str());
    }

    void report_progress(int percent) {
        yuzu_ctx_report_progress(raw_, percent);
    }

private:
    YuzuCommandContext* raw_;
};

// ── Plugin context wrapper ────────────────────────────────────────────────────

class PluginContext {
public:
    explicit PluginContext(YuzuPluginContext* raw) noexcept : raw_{raw} {}

    [[nodiscard]] std::string_view get_config(std::string_view key) const noexcept {
        const char* v = yuzu_ctx_get_config(raw_, std::string{key}.c_str());
        return v ? v : std::string_view{};
    }

    [[nodiscard]] std::string_view get_secret(std::string_view key) const noexcept {
        const char* v = yuzu_ctx_get_secret(raw_, std::string{key}.c_str());
        return v ? v : std::string_view{};
    }

private:
    YuzuPluginContext* raw_;
};

// ── Plugin base class ─────────────────────────────────────────────────────────

/**
 * Derive from yuzu::Plugin to implement a plugin in C++.
 * Then use YUZU_PLUGIN_EXPORT(YourClass) at namespace scope in the .cpp file.
 */
class Plugin {
public:
    virtual ~Plugin() = default;

    [[nodiscard]] virtual std::string_view name()        const noexcept = 0;
    [[nodiscard]] virtual std::string_view version()     const noexcept = 0;
    [[nodiscard]] virtual std::string_view description() const noexcept = 0;

    /**
     * Return a null-terminated list of action strings this plugin handles.
     * The returned pointer must be valid for the lifetime of the plugin.
     */
    [[nodiscard]] virtual const char* const* actions() const noexcept = 0;

    /**
     * Called once after the shared library is loaded.
     * @return Result<void> — return an error to abort loading.
     */
    virtual Result<void> init(PluginContext& ctx) = 0;

    /**
     * Called once before the shared library is unloaded.
     */
    virtual void shutdown(PluginContext& ctx) noexcept = 0;

    /**
     * Dispatch an action. Called from the agent on the agent's thread pool.
     * Thread-safety: the agent may call this concurrently for different command IDs.
     * @return 0 on success, non-zero error code on failure.
     */
    virtual int execute(CommandContext& ctx,
                        std::string_view action,
                        Params params) = 0;
};

}  // namespace yuzu

// ── Export macro ──────────────────────────────────────────────────────────────

/**
 * Place YUZU_PLUGIN_EXPORT(MyPlugin) in exactly one .cpp file of your plugin.
 * It generates the static descriptor and the required C export symbol.
 *
 * Example:
 *   class InventoryPlugin final : public yuzu::Plugin { ... };
 *   YUZU_PLUGIN_EXPORT(InventoryPlugin)
 */
#define YUZU_PLUGIN_EXPORT(ClassName)                                          \
    static ClassName _yuzu_plugin_instance_{};                                 \
                                                                               \
    /* Trampoline: init */                                                     \
    static int _yuzu_init_(YuzuPluginContext* ctx) {                           \
        yuzu::PluginContext wrap{ctx};                                          \
        auto res = _yuzu_plugin_instance_.init(wrap);                          \
        return res ? 0 : res.error().code;                                     \
    }                                                                          \
                                                                               \
    /* Trampoline: shutdown */                                                  \
    static void _yuzu_shutdown_(YuzuPluginContext* ctx) {                      \
        yuzu::PluginContext wrap{ctx};                                          \
        _yuzu_plugin_instance_.shutdown(wrap);                                 \
    }                                                                          \
                                                                               \
    /* Trampoline: execute */                                                  \
    static int _yuzu_execute_(YuzuCommandContext* ctx,                         \
                               const char* action,                             \
                               const YuzuParam* params,                        \
                               size_t param_count) {                           \
        yuzu::CommandContext cmd_ctx{ctx};                                     \
        yuzu::Params         p{{params, param_count}};                         \
        return _yuzu_plugin_instance_.execute(cmd_ctx, action, p);             \
    }                                                                          \
                                                                               \
    static const YuzuPluginDescriptor _yuzu_descriptor_{                       \
        .abi_version = YUZU_PLUGIN_ABI_VERSION,                                \
        .name        = []() { return std::string{                              \
                           _yuzu_plugin_instance_.name()}.c_str(); }(),        \
        .version     = []() { return std::string{                              \
                           _yuzu_plugin_instance_.version()}.c_str(); }(),     \
        .description = []() { return std::string{                              \
                           _yuzu_plugin_instance_.description()}.c_str(); }(), \
        .actions     = _yuzu_plugin_instance_.actions(),                       \
        .init        = _yuzu_init_,                                            \
        .shutdown    = _yuzu_shutdown_,                                        \
        .execute     = _yuzu_execute_,                                         \
    };                                                                         \
                                                                               \
    extern "C" YUZU_PLUGIN_API                                                 \
    const YuzuPluginDescriptor* yuzu_plugin_descriptor(void) {                 \
        return &_yuzu_descriptor_;                                             \
    }
