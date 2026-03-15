/**
 * diagnostics_plugin.cpp — Agent diagnostics plugin for Yuzu
 *
 * Actions:
 *   "log_level"       — Read current log level from config.
 *   "certificates"    — List TLS cert paths and whether they exist.
 *   "connection_info" — Report server address and TLS status from config.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 */

#include <yuzu/plugin.hpp>

#include <filesystem>
#include <format>
#include <string>
#include <string_view>

namespace {

YuzuPluginContext* g_ctx = nullptr;

} // namespace

class DiagnosticsPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "diagnostics"; }
    std::string_view version()     const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Agent diagnostics — log level, certificates, connection info";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = { "log_level", "certificates", "connection_info", nullptr };
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        g_ctx = ctx.raw();
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
        g_ctx = nullptr;
    }

    int execute(yuzu::CommandContext& ctx,
                std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "log_level") {
            return do_log_level(ctx);
        }
        if (action == "certificates") {
            return do_certificates(ctx);
        }
        if (action == "connection_info") {
            return do_connection_info(ctx);
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_log_level(yuzu::CommandContext& ctx) {
        yuzu::PluginContext pctx{g_ctx};
        auto level = pctx.get_config("agent.log_level");
        if (level.empty()) {
            level = "info";
        }
        ctx.write_output(std::format("log_level|{}", level));
        return 0;
    }

    int do_certificates(yuzu::CommandContext& ctx) {
        yuzu::PluginContext pctx{g_ctx};

        struct CertInfo {
            const char* type;
            const char* config_key;
        };

        static constexpr CertInfo certs[] = {
            {"ca_cert",     "tls.ca_cert"},
            {"client_cert", "tls.client_cert"},
            {"client_key",  "tls.client_key"},
        };

        for (const auto& ci : certs) {
            auto path = pctx.get_config(ci.config_key);
            std::string path_str{path};
            bool exists = false;
            if (!path_str.empty()) {
                std::error_code ec;
                exists = std::filesystem::exists(path_str, ec);
            }
            ctx.write_output(std::format("cert|{}|{}|{}",
                ci.type,
                path_str.empty() ? "(not configured)" : path_str,
                exists ? "true" : "false"));
        }
        return 0;
    }

    int do_connection_info(yuzu::CommandContext& ctx) {
        yuzu::PluginContext pctx{g_ctx};

        auto server_addr = pctx.get_config("agent.server_address");
        auto tls_enabled = pctx.get_config("tls.enabled");

        ctx.write_output(std::format("server_address|{}",
            server_addr.empty() ? "(not configured)" : std::string{server_addr}));
        ctx.write_output(std::format("tls_enabled|{}",
            tls_enabled.empty() ? "false" : std::string{tls_enabled}));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(DiagnosticsPlugin)
