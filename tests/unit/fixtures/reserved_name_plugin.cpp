// Fixture plugin for #453 — deliberately declares a reserved plugin name
// (`__guard__`) so PluginLoader::scan can be exercised against the
// reserved-name rejection path. Not shipped; linked only when
// -Dbuild_tests=true.

#include <yuzu/plugin.hpp>

#include <string_view>

class ReservedNameFixturePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "__guard__"; }
    std::string_view version() const noexcept override { return "0.0.0-test"; }
    std::string_view description() const noexcept override {
        return "Fixture — must be rejected by plugin loader (#453)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext&) override { return {}; }
    void shutdown(yuzu::PluginContext&) noexcept override {}
    int execute(yuzu::CommandContext&, std::string_view, yuzu::Params) override { return 0; }
};

YUZU_PLUGIN_EXPORT(ReservedNameFixturePlugin)
