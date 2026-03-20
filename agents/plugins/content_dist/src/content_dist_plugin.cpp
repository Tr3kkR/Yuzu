/**
 * content_dist_plugin.cpp — Content staging plugin for Yuzu
 *
 * Actions:
 *   "stage"          — Download a file to staging dir with hash verification.
 *   "execute_staged" — Execute a previously staged file.
 *   "list_staged"    — List files in the staging directory.
 *   "cleanup"        — Remove staged files older than N hours.
 */

#include <yuzu/plugin.hpp>

#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
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
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif

namespace fs = std::filesystem;

namespace {

YuzuPluginContext* g_ctx = nullptr;

fs::path staging_dir() {
    yuzu::PluginContext pctx{g_ctx};
    auto data_dir = pctx.get_config("agent.data_dir");
    fs::path dir = data_dir.empty() ? fs::temp_directory_path() / "yuzu-staged" : fs::path{std::string{data_dir}} / "staged";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

std::string sha256_file(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    DWORD hash_len = 0, result_len = 0;
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &result_len, 0);
    BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0)
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf), static_cast<ULONG>(file.gcount()), 0);
    std::vector<UCHAR> digest(hash_len);
    BCryptFinishHash(hash, digest.data(), hash_len, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    std::string hex;
    for (auto b : digest) hex += std::format("{:02x}", b);
    return hex;
#else
    auto* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0)
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(file.gcount()));
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);
    std::string hex;
    for (unsigned i = 0; i < len; ++i) hex += std::format("{:02x}", digest[i]);
    return hex;
#endif
}

bool is_safe_filename(std::string_view name) {
    if (name.empty() || name.find("..") != std::string_view::npos) return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_')
            return false;
    }
    return true;
}

} // namespace

class ContentDistPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "content_dist"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Content staging — download, verify, execute, and manage staged files";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"stage", "execute_staged", "list_staged", "cleanup", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override { g_ctx = ctx.raw(); return {}; }
    void shutdown(yuzu::PluginContext&) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "stage")          return do_stage(ctx, params);
        if (action == "execute_staged") return do_execute(ctx, params);
        if (action == "list_staged")    return do_list(ctx);
        if (action == "cleanup")        return do_cleanup(ctx, params);
        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

private:
    int do_stage(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto url = params.get("url");
        auto filename = params.get("filename");
        auto expected = params.get("sha256");
        if (url.empty() || filename.empty() || expected.empty()) {
            ctx.write_output("error|missing required parameters: url, filename, sha256");
            return 1;
        }
        if (!is_safe_filename(filename)) {
            ctx.write_output("error|invalid filename (alphanumeric, dots, hyphens, underscores only)");
            return 1;
        }

        auto dest = staging_dir() / std::string{filename};
        std::string cmd;
#ifdef _WIN32
        cmd = std::format("powershell -NoProfile -Command \"Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing\"",
                          url, dest.string());
#else
        cmd = std::format("curl -fsSL -o '{}' '{}'", dest.string(), url);
#endif
        if (std::system(cmd.c_str()) != 0) {
            ctx.write_output("error|download failed");
            return 1;
        }

        auto hash = sha256_file(dest);
        if (hash != expected) {
            std::error_code ec;
            fs::remove(dest, ec);
            ctx.write_output(std::format("error|hash mismatch: expected={}, got={}", expected, hash));
            return 1;
        }

        ctx.write_output("status|ok");
        ctx.write_output(std::format("staged_path|{}", dest.string()));
        return 0;
    }

    int do_execute(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto filename = params.get("filename");
        if (filename.empty()) { ctx.write_output("error|missing required parameter: filename"); return 1; }
        if (!is_safe_filename(filename)) { ctx.write_output("error|invalid filename"); return 1; }

        auto path = staging_dir() / std::string{filename};
        if (!fs::exists(path)) {
            ctx.write_output(std::format("error|file not staged: {}", filename));
            return 1;
        }

        auto args = params.get("args");
        std::string cmd = "\"" + path.string() + "\"";
        if (!args.empty()) cmd += " " + std::string{args};

#ifdef _WIN32
        FILE* pipe = _popen(cmd.c_str(), "r");
#else
        // Make executable on Unix
        fs::permissions(path, fs::perms::owner_exec, fs::perm_options::add);
        FILE* pipe = popen(cmd.c_str(), "r");
#endif
        if (!pipe) { ctx.write_output("error|failed to execute"); return 1; }

        char buf[1024];
        std::string output;
        while (fgets(buf, sizeof(buf), pipe)) output += buf;
#ifdef _WIN32
        int rc = _pclose(pipe);
#else
        int rc = pclose(pipe);
#endif
        ctx.write_output(std::format("status|{}", rc == 0 ? "ok" : "error"));
        ctx.write_output(std::format("exit_code|{}", rc));
        if (!output.empty()) ctx.write_output(std::format("output|{}", output));
        return rc;
    }

    int do_list(yuzu::CommandContext& ctx) {
        auto dir = staging_dir();
        std::error_code ec;
        int count = 0;
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (!entry.is_regular_file()) continue;
            auto size = entry.file_size(ec);
            auto hash = sha256_file(entry.path());
            ctx.write_output(std::format("file|{}|{}|{}", entry.path().filename().string(), size, hash));
            ++count;
        }
        ctx.write_output(std::format("count|{}", count));
        return 0;
    }

    int do_cleanup(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto hours_str = params.get("hours");
        int hours = 24;
        if (!hours_str.empty()) { try { hours = std::stoi(std::string{hours_str}); } catch (...) {} }

        auto dir = staging_dir();
        auto cutoff = fs::file_time_type::clock::now() - std::chrono::hours(hours);
        std::error_code ec;
        int removed = 0;
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (entry.is_regular_file() && entry.last_write_time(ec) < cutoff) {
                fs::remove(entry.path(), ec);
                ++removed;
            }
        }
        ctx.write_output(std::format("removed|{}", removed));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(ContentDistPlugin)
