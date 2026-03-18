#include <yuzu/agent/plugin_loader.hpp>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>

TEST_CASE("PluginLoader returns empty result for nonexistent directory", "[plugin_loader]") {
    auto result = yuzu::agent::PluginLoader::scan("/nonexistent/path");
    REQUIRE(result.loaded.empty());
    REQUIRE(result.errors.empty());
}

TEST_CASE("PluginLoader returns empty result for empty directory", "[plugin_loader]") {
    auto tmp = std::filesystem::temp_directory_path() / "yuzu_test_empty_plugins";
    std::filesystem::create_directories(tmp);

    auto result = yuzu::agent::PluginLoader::scan(tmp);
    REQUIRE(result.loaded.empty());
    REQUIRE(result.errors.empty());

    std::filesystem::remove(tmp);
}
