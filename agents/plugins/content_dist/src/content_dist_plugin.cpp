/**
 * content_dist_plugin.cpp — Content staging plugin for Yuzu
 *
 * Actions:
 *   "stage"          — Download a file to staging dir with hash verification.
 *   "execute_staged" — Execute a previously staged file.
 *   "list_staged"    — List files in the staging directory.
 *   "cleanup"        — Remove staged files older than N hours.
 *
 * Security: uses cpp-httplib for downloads (no shell invocation).
 *           execute_staged uses CreateProcessW/fork+execvp (no shell interpretation).
 *           Args validated to block shell metacharacters.
 */

#include <yuzu/plugin.hpp>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <httplib.h>

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

// ── URL parsing (same as http_client) ───────────────────────────────────────

struct ParsedUrl {
    bool is_https = false;
    std::string host;
    int port = 0;
    std::string path;
};

bool parse_url(std::string_view url, ParsedUrl& out) {
    if (url.starts_with("https://")) {
        out.is_https = true;
        url.remove_prefix(8);
    } else if (url.starts_with("http://")) {
        out.is_https = false;
        url.remove_prefix(7);
    } else {
        return false;
    }

    auto slash_pos = url.find('/');
    std::string_view authority;
    if (slash_pos != std::string_view::npos) {
        authority = url.substr(0, slash_pos);
        out.path = std::string(url.substr(slash_pos));
    } else {
        authority = url;
        out.path = "/";
    }

    auto colon_pos = authority.rfind(':');
    auto bracket_pos = authority.find(']');
    if (colon_pos != std::string_view::npos &&
        (bracket_pos == std::string_view::npos || colon_pos > bracket_pos)) {
        out.host = std::string(authority.substr(0, colon_pos));
        auto port_str = authority.substr(colon_pos + 1);
        try { out.port = std::stoi(std::string(port_str)); } catch (...) { out.port = 0; }
    } else {
        out.host = std::string(authority);
        out.port = 0;
    }

    if (out.port == 0) {
        out.port = out.is_https ? 443 : 80;
    }

    return !out.host.empty();
}

// Download via httplib — no shell invocation
int download_file(std::string_view url, const fs::path& dest, std::string& error) {
    ParsedUrl parsed;
    if (!parse_url(url, parsed)) {
        error = "invalid URL";
        return 1;
    }

    std::ofstream ofs(dest, std::ios::binary);
    if (!ofs) {
        error = "failed to open destination file";
        return 1;
    }

    auto content_receiver = [&](const char* data, size_t len) {
        ofs.write(data, static_cast<std::streamsize>(len));
        return true;
    };

    httplib::Result res;
    if (parsed.is_https) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        httplib::SSLClient cli(parsed.host, parsed.port);
        cli.set_connection_timeout(30);
        cli.set_read_timeout(300);
        cli.enable_server_certificate_verification(true);
        res = cli.Get(parsed.path, content_receiver);
#else
        ofs.close();
        error = "HTTPS not supported (OpenSSL not available)";
        return 1;
#endif
    } else {
        httplib::Client cli(parsed.host, parsed.port);
        cli.set_connection_timeout(30);
        cli.set_read_timeout(300);
        res = cli.Get(parsed.path, content_receiver);
    }

    ofs.close();
    if (!res || res->status < 200 || res->status >= 400) {
        error = "download failed: HTTP " + (res ? std::to_string(res->status) : "connection error");
        return 1;
    }

    return 0;
}

// ── Safe argument validation and splitting ──────────────────────────────────

// Validate args contain no shell metacharacters
bool is_safe_arg(std::string_view arg) {
    // Allow alphanumeric, dash, underscore, dot, equals, colon, slash, backslash, space
    // Block: ; & | ` $ ( ) { } < > ! ~ ^ " ' # * ? [ ] \n \r
    for (char c : arg) {
        if (c == ';' || c == '&' || c == '|' || c == '`' || c == '$' ||
            c == '(' || c == ')' || c == '{' || c == '}' || c == '<' ||
            c == '>' || c == '!' || c == '~' || c == '^' || c == '\'' ||
            c == '"' || c == '#' || c == '*' || c == '?' || c == '[' ||
            c == ']' || c == '\n' || c == '\r') {
            return false;
        }
    }
    return true;
}

// Split a string by spaces into argument vector (simple split, no shell parsing)
std::vector<std::string> split_args(std::string_view args) {
    std::vector<std::string> result;
    std::string current;
    for (char c : args) {
        if (c == ' ' || c == '\t') {
            if (!current.empty()) {
                result.push_back(std::move(current));
                current.clear();
            }
        } else {
            current += c;
        }
    }
    if (!current.empty()) result.push_back(std::move(current));
    return result;
}

// ── Safe process execution (no shell) ───────────────────────────────────────

#ifdef _WIN32

// Windows: CreateProcessW — no shell interpretation
int safe_execute(const fs::path& exe_path, std::string_view args_str, std::string& output) {
    // Build command line: "path" arg1 arg2 ...
    std::wstring wpath = exe_path.wstring();
    std::wstring cmdline = L"\"" + wpath + L"\"";

    if (!args_str.empty()) {
        int len = MultiByteToWideChar(CP_UTF8, 0, args_str.data(),
                                       static_cast<int>(args_str.size()), nullptr, 0);
        std::wstring wargs(static_cast<size_t>(len), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, args_str.data(),
                             static_cast<int>(args_str.size()), wargs.data(), len);
        cmdline += L" " + wargs;
    }

    // Create pipes for stdout capture
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE stdout_rd = nullptr, stdout_wr = nullptr;
    if (!CreatePipe(&stdout_rd, &stdout_wr, &sa, 0)) {
        output = "failed to create pipe";
        return -1;
    }
    SetHandleInformation(stdout_rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.hStdOutput = stdout_wr;
    si.hStdError = stdout_wr;
    si.dwFlags = STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(
        wpath.c_str(),      // application name
        cmdline.data(),     // command line (mutable)
        nullptr,            // process security attributes
        nullptr,            // thread security attributes
        TRUE,               // inherit handles
        CREATE_NO_WINDOW,   // creation flags — no console window
        nullptr,            // environment
        nullptr,            // current directory
        &si,                // startup info
        &pi                 // process info
    );

    CloseHandle(stdout_wr); // close write end in parent

    if (!ok) {
        CloseHandle(stdout_rd);
        output = "CreateProcessW failed: " + std::to_string(GetLastError());
        return -1;
    }

    // Read stdout
    char buf[1024];
    DWORD bytes_read = 0;
    while (ReadFile(stdout_rd, buf, sizeof(buf) - 1, &bytes_read, nullptr) && bytes_read > 0) {
        buf[bytes_read] = '\0';
        output += buf;
    }
    CloseHandle(stdout_rd);

    // Wait for process
    WaitForSingleObject(pi.hProcess, 30000); // 30 second timeout
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return static_cast<int>(exit_code);
}

#else

// Unix: fork + execvp — no shell interpretation
int safe_execute(const fs::path& exe_path, std::string_view args_str, std::string& output) {
    // Make executable
    std::error_code ec;
    fs::permissions(exe_path, fs::perms::owner_exec, fs::perm_options::add, ec);

    auto args = split_args(args_str);

    // Build argv
    std::vector<const char*> argv;
    std::string exe_str = exe_path.string();
    argv.push_back(exe_str.c_str());
    for (const auto& a : args) argv.push_back(a.c_str());
    argv.push_back(nullptr);

    // Create pipe for stdout capture
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        output = "failed to create pipe";
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        output = "fork failed";
        return -1;
    }

    if (pid == 0) {
        // Child
        close(pipefd[0]); // close read end
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        execvp(exe_str.c_str(), const_cast<char* const*>(argv.data()));
        _exit(127); // execvp failed
    }

    // Parent
    close(pipefd[1]); // close write end

    char buf[1024];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        output += buf;
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

#endif

} // namespace

class ContentDistPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "content_dist"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Content staging — download, verify, execute, and manage staged files (no shell-out)";
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
        std::string error;
        if (download_file(url, dest, error) != 0) {
            ctx.write_output(std::format("error|{}", error));
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
        // Validate args to block shell metacharacters
        if (!args.empty() && !is_safe_arg(args)) {
            ctx.write_output("error|args contain forbidden characters (shell metacharacters blocked)");
            return 1;
        }

        std::string output;
        int rc = safe_execute(path, args, output);

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
