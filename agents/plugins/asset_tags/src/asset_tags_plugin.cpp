/**
 * asset_tags_plugin.cpp — Structured asset tag awareness for Yuzu agents
 *
 * This plugin lets agents learn their server-assigned structured tags
 * (role, environment, location, service) and detect when they change.
 *
 * Actions:
 *   "sync"     — Server pushes the current structured tags. The plugin
 *                stores them locally, detects changes from the previous
 *                state, and reports any diffs.
 *   "status"   — Reports the locally cached tags and sync metadata.
 *   "get"      — Get a specific structured tag value by category key.
 *   "changes"  — Reports the change log (what changed and when).
 *
 * Storage: <data_dir>/asset_tags.json
 *
 * Background: A periodic check thread runs every check_interval seconds
 * (default 300). It marks the local cache as stale if no sync has arrived
 * within that window, writing a stale flag that the "status" action reports.
 */

#include <yuzu/plugin.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

namespace fs = std::filesystem;

// The 4 fixed structured tag categories
constexpr std::string_view kCategoryKeys[] = {"role", "environment", "location", "service"};

struct ChangeRecord {
    std::string key;
    std::string old_value;
    std::string new_value;
    int64_t timestamp{0}; // epoch seconds
};

struct AssetTagState {
    std::unordered_map<std::string, std::string> tags;
    int64_t last_sync_epoch{0};
    bool stale{true};
    std::vector<ChangeRecord> change_log;
};

std::mutex g_mu;
AssetTagState g_state;
fs::path g_store_path;
std::atomic<bool> g_shutdown{false};
std::thread g_check_thread;
int g_check_interval_s{300}; // default 5 minutes

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void load_state() {
    std::lock_guard lock(g_mu);
    g_state = {};

    if (g_store_path.empty())
        return;

    std::error_code ec;
    if (!fs::exists(g_store_path, ec))
        return;

    std::ifstream f(g_store_path);
    if (!f)
        return;

    try {
        auto j = nlohmann::json::parse(f);
        if (j.contains("tags") && j["tags"].is_object()) {
            for (auto& [key, val] : j["tags"].items()) {
                if (val.is_string())
                    g_state.tags[key] = val.get<std::string>();
            }
        }
        if (j.contains("last_sync_epoch"))
            g_state.last_sync_epoch = j["last_sync_epoch"].get<int64_t>();
        if (j.contains("stale"))
            g_state.stale = j["stale"].get<bool>();
        if (j.contains("change_log") && j["change_log"].is_array()) {
            for (const auto& entry : j["change_log"]) {
                ChangeRecord cr;
                cr.key = entry.value("key", "");
                cr.old_value = entry.value("old_value", "");
                cr.new_value = entry.value("new_value", "");
                cr.timestamp = entry.value("timestamp", int64_t{0});
                g_state.change_log.push_back(std::move(cr));
            }
        }
    } catch (...) {}
}

void save_state() {
    if (g_store_path.empty())
        return;

    std::error_code ec;
    auto parent = g_store_path.parent_path();
    if (!parent.empty())
        fs::create_directories(parent, ec);

    nlohmann::json j;
    {
        std::lock_guard lock(g_mu);
        j["tags"] = g_state.tags;
        j["last_sync_epoch"] = g_state.last_sync_epoch;
        j["stale"] = g_state.stale;

        nlohmann::json log_arr = nlohmann::json::array();
        // Keep only last 50 changes
        size_t start = g_state.change_log.size() > 50 ? g_state.change_log.size() - 50 : 0;
        for (size_t i = start; i < g_state.change_log.size(); ++i) {
            const auto& cr = g_state.change_log[i];
            log_arr.push_back({{"key", cr.key},
                               {"old_value", cr.old_value},
                               {"new_value", cr.new_value},
                               {"timestamp", cr.timestamp}});
        }
        j["change_log"] = log_arr;
    }

    std::ofstream f(g_store_path);
    if (f)
        f << j.dump(2);
}

void check_thread_fn() {
    while (!g_shutdown.load(std::memory_order_acquire)) {
        // Sleep in small increments for responsive shutdown
        auto remaining = std::chrono::seconds{g_check_interval_s};
        while (remaining.count() > 0 && !g_shutdown.load(std::memory_order_acquire)) {
            auto sleep_time = std::min(remaining, std::chrono::seconds{5});
            std::this_thread::sleep_for(sleep_time);
            remaining -= sleep_time;
        }
        if (g_shutdown.load(std::memory_order_acquire))
            break;

        // Check if tags are stale (no sync within the check interval)
        std::lock_guard lock(g_mu);
        auto now = now_epoch();
        if (g_state.last_sync_epoch > 0 &&
            (now - g_state.last_sync_epoch) > g_check_interval_s) {
            if (!g_state.stale) {
                g_state.stale = true;
                // Save updated stale flag
            }
        }
    }
}

} // namespace

class AssetTagsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "asset_tags"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Structured asset tag awareness — syncs server-assigned tags locally and detects "
               "changes";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"sync", "status", "get", "changes", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        yuzu::PluginContext pctx{ctx.raw()};
        auto data_dir = pctx.get_config("agent.data_dir");
        if (!data_dir.empty())
            g_store_path = fs::path(std::string{data_dir}) / "asset_tags.json";

        // Read optional check interval from config (default 300s)
        auto interval_str = pctx.get_config("asset_tags.check_interval");
        if (!interval_str.empty()) {
            try {
                g_check_interval_s = std::stoi(std::string{interval_str});
                if (g_check_interval_s < 30)
                    g_check_interval_s = 30; // floor at 30s
            } catch (...) {}
        }

        load_state();

        // Start background staleness check thread
        g_shutdown.store(false, std::memory_order_release);
        g_check_thread = std::thread(check_thread_fn);

        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
        g_shutdown.store(true, std::memory_order_release);
        if (g_check_thread.joinable())
            g_check_thread.join();
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "sync")
            return do_sync(ctx, params);
        if (action == "status")
            return do_status(ctx);
        if (action == "get")
            return do_get(ctx, params);
        if (action == "changes")
            return do_changes(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_sync(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto now = now_epoch();
        std::vector<ChangeRecord> new_changes;

        {
            std::lock_guard lock(g_mu);

            for (auto cat_key : kCategoryKeys) {
                std::string key_str{cat_key};
                auto new_value = std::string{params.get(cat_key)};

                auto it = g_state.tags.find(key_str);
                std::string old_value = (it != g_state.tags.end()) ? it->second : "";

                if (new_value != old_value) {
                    ChangeRecord cr;
                    cr.key = key_str;
                    cr.old_value = old_value;
                    cr.new_value = new_value;
                    cr.timestamp = now;
                    new_changes.push_back(cr);
                    g_state.change_log.push_back(cr);
                }

                if (new_value.empty()) {
                    g_state.tags.erase(key_str);
                } else {
                    g_state.tags[key_str] = new_value;
                }
            }

            g_state.last_sync_epoch = now;
            g_state.stale = false;
        }

        save_state();

        // Report results
        if (new_changes.empty()) {
            ctx.write_output("sync|no_changes");
        } else {
            for (const auto& cr : new_changes) {
                if (cr.old_value.empty()) {
                    ctx.write_output(
                        std::format("sync|tag_added|{}|{}", cr.key, cr.new_value));
                } else if (cr.new_value.empty()) {
                    ctx.write_output(
                        std::format("sync|tag_removed|{}|{}", cr.key, cr.old_value));
                } else {
                    ctx.write_output(std::format("sync|tag_changed|{}|{}|{}", cr.key,
                                                 cr.old_value, cr.new_value));
                }
            }
        }

        // Report current state
        std::lock_guard lock(g_mu);
        for (auto cat_key : kCategoryKeys) {
            std::string key_str{cat_key};
            auto it = g_state.tags.find(key_str);
            auto val = (it != g_state.tags.end()) ? it->second : "";
            ctx.write_output(std::format("tag|{}|{}", key_str, val));
        }
        ctx.write_output(std::format("last_sync|{}", g_state.last_sync_epoch));
        return 0;
    }

    int do_status(yuzu::CommandContext& ctx) {
        std::lock_guard lock(g_mu);

        for (auto cat_key : kCategoryKeys) {
            std::string key_str{cat_key};
            auto it = g_state.tags.find(key_str);
            auto val = (it != g_state.tags.end()) ? it->second : "";
            ctx.write_output(std::format("tag|{}|{}", key_str, val));
        }

        ctx.write_output(std::format("last_sync|{}", g_state.last_sync_epoch));
        ctx.write_output(std::format("stale|{}", g_state.stale ? "true" : "false"));
        ctx.write_output(std::format("check_interval|{}", g_check_interval_s));
        ctx.write_output(std::format("change_count|{}", g_state.change_log.size()));
        return 0;
    }

    int do_get(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto key = params.get("key");
        if (key.empty()) {
            ctx.write_output("error|missing required parameter: key");
            return 1;
        }

        std::string key_str{key};

        // Validate it's a known category
        bool valid = false;
        for (auto cat_key : kCategoryKeys) {
            if (cat_key == key_str) {
                valid = true;
                break;
            }
        }
        if (!valid) {
            ctx.write_output(std::format("error|unknown category: {}", key_str));
            return 1;
        }

        std::lock_guard lock(g_mu);
        auto it = g_state.tags.find(key_str);
        auto val = (it != g_state.tags.end()) ? it->second : "";
        ctx.write_output(std::format("tag|{}|{}", key_str, val));
        return 0;
    }

    int do_changes(yuzu::CommandContext& ctx) {
        std::lock_guard lock(g_mu);

        if (g_state.change_log.empty()) {
            ctx.write_output("changes|none");
            return 0;
        }

        for (const auto& cr : g_state.change_log) {
            ctx.write_output(std::format("change|{}|{}|{}|{}", cr.key, cr.old_value,
                                         cr.new_value, cr.timestamp));
        }
        ctx.write_output(std::format("total_changes|{}", g_state.change_log.size()));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(AssetTagsPlugin)
