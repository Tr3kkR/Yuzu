/**
 * http_client_plugin.cpp — HTTP client plugin for Yuzu
 *
 * Actions:
 *   "download" — Download a file from URL to local path with optional hash verification.
 *                Params: url (required), path (required), expected_hash (optional SHA256).
 *   "get"      — HTTP GET a URL, return status + body.
 *                Params: url (required).
 *   "head"     — HTTP HEAD a URL, return status + headers.
 *                Params: url (required).
 *
 * Output: pipe-delimited via write_output()
 */

#include <yuzu/plugin.hpp>

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
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/evp.h>
#endif

namespace fs = std::filesystem;

namespace {

YuzuPluginContext* g_ctx = nullptr;

bool is_valid_url(std::string_view url) {
    return url.starts_with("http://") || url.starts_with("https://");
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
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf), static_cast<ULONG>(file.gcount()), 0);
    }

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
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(file.gcount()));
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);

    std::string hex;
    for (unsigned i = 0; i < len; ++i) hex += std::format("{:02x}", digest[i]);
    return hex;
#endif
}

// Simple HTTP download using platform tools
// Uses PowerShell on Windows, curl on Linux/macOS
int download_url(std::string_view url, const fs::path& dest, std::string& error) {
    std::string cmd;
#ifdef _WIN32
    cmd = std::format(
        "powershell -NoProfile -Command \"Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing\"",
        url, dest.string());
#else
    cmd = std::format("curl -fsSL -o '{}' '{}'", dest.string(), url);
#endif
    int rc = std::system(cmd.c_str());
    if (rc != 0) {
        error = "download failed with exit code " + std::to_string(rc);
    }
    return rc;
}

std::string http_get(std::string_view url, int& status_code) {
    std::string result;
#ifdef _WIN32
    auto cmd = std::format(
        "powershell -NoProfile -Command \"try {{ $r = Invoke-WebRequest -Uri '{}' -UseBasicParsing; Write-Host $r.StatusCode; Write-Host $r.Content }} catch {{ Write-Host $_.Exception.Response.StatusCode.Value__; Write-Host $_.ErrorDetails.Message }}\"",
        url);
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    auto cmd = std::format("curl -sS -w '\\n%{{http_code}}' '{}'", url);
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe) { status_code = 0; return "failed to execute"; }

    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) result += buf;
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif

    // Parse status code from last line
    auto last_nl = result.rfind('\n', result.size() - 2);
    if (last_nl != std::string::npos) {
        auto code_str = result.substr(last_nl + 1);
        while (!code_str.empty() && (code_str.back() == '\n' || code_str.back() == '\r'))
            code_str.pop_back();
        try { status_code = std::stoi(code_str); } catch (...) { status_code = 0; }
        result = result.substr(0, last_nl);
    } else {
        status_code = 200;
    }
    return result;
}

} // namespace

class HttpClientPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "http_client"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "HTTP client — download files, GET/HEAD requests with hash verification";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"download", "get", "head", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        g_ctx = ctx.raw();
        return {};
    }

    void shutdown(yuzu::PluginContext&) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "download") return do_download(ctx, params);
        if (action == "get")      return do_get(ctx, params);
        if (action == "head")     return do_head(ctx, params);
        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

private:
    int do_download(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto url = params.get("url");
        auto path = params.get("path");
        if (url.empty() || path.empty()) {
            ctx.write_output("error|missing required parameters: url, path");
            return 1;
        }
        if (!is_valid_url(url)) {
            ctx.write_output("error|only http:// and https:// URLs are allowed");
            return 1;
        }

        fs::path dest{std::string{path}};
        std::string error;
        if (download_url(url, dest, error) != 0) {
            ctx.write_output(std::format("error|{}", error));
            return 1;
        }

        std::error_code ec;
        auto size = fs::file_size(dest, ec);
        auto hash = sha256_file(dest);

        auto expected = params.get("expected_hash");
        if (!expected.empty() && hash != expected) {
            fs::remove(dest, ec);
            ctx.write_output(std::format("error|hash mismatch: expected={}, got={}", expected, hash));
            return 1;
        }

        ctx.write_output("status|ok");
        ctx.write_output(std::format("path|{}", dest.string()));
        ctx.write_output(std::format("size|{}", size));
        ctx.write_output(std::format("hash|{}", hash));
        return 0;
    }

    int do_get(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto url = params.get("url");
        if (url.empty()) { ctx.write_output("error|missing required parameter: url"); return 1; }
        if (!is_valid_url(url)) { ctx.write_output("error|only http:// and https:// URLs allowed"); return 1; }

        int status = 0;
        auto body = http_get(url, status);
        ctx.write_output(std::format("status|{}", status));
        ctx.write_output(std::format("body|{}", body));
        return status >= 200 && status < 400 ? 0 : 1;
    }

    int do_head(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto url = params.get("url");
        if (url.empty()) { ctx.write_output("error|missing required parameter: url"); return 1; }
        if (!is_valid_url(url)) { ctx.write_output("error|only http:// and https:// URLs allowed"); return 1; }

        std::string cmd;
#ifdef _WIN32
        cmd = std::format("powershell -NoProfile -Command \"(Invoke-WebRequest -Uri '{}' -Method Head -UseBasicParsing).Headers | ConvertTo-Json\"", url);
        FILE* pipe = _popen(cmd.c_str(), "r");
#else
        cmd = std::format("curl -sI '{}'", url);
        FILE* pipe = popen(cmd.c_str(), "r");
#endif
        if (!pipe) { ctx.write_output("error|failed to execute head request"); return 1; }

        char buf[1024];
        std::string output;
        while (fgets(buf, sizeof(buf), pipe)) output += buf;
#ifdef _WIN32
        _pclose(pipe);
#else
        pclose(pipe);
#endif
        ctx.write_output(std::format("headers|{}", output));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(HttpClientPlugin)
