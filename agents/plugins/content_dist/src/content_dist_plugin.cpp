/**
 * content_dist_plugin.cpp — Content staging plugin for Yuzu
 *
 * Actions:
 *   "stage"          — Download a file to staging dir with hash verification.
 *   "execute_staged" — Execute a previously staged file.
 *   "list_staged"    — List files in the staging directory.
 *   "cleanup"        — Remove staged files older than N hours.
 *   "upload_file"    — Upload a local file to the Yuzu server via the
 *                       one-time upload-grant + authenticated chunked
 *                       receive protocol (PR1.6, CC-06).
 *
 * Security: uses cpp-httplib for downloads/uploads (no shell invocation).
 *           execute_staged uses CreateProcessW/fork+execvp (no shell interpretation).
 *           Args validated to block shell metacharacters.
 */

#include <yuzu/plugin.hpp>

#include "content_dist_upload_parsers.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <yuzu/agent/fork_lock.hpp> // BR-001: process-wide fork/CLOEXEC serialization

#include <openssl/evp.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <httplib.h>

namespace fs = std::filesystem;
namespace up = yuzu::content_dist::upload;

namespace {

YuzuPluginContext* g_ctx = nullptr;

fs::path staging_dir() {
    yuzu::PluginContext pctx{g_ctx};
    auto data_dir = pctx.get_config("agent.data_dir");
    fs::path dir = data_dir.empty() ? fs::temp_directory_path() / "yuzu-staged"
                                    : fs::path{std::string{data_dir}} / "staged";
    std::error_code ec;
    fs::create_directories(dir, ec);
#ifndef _WIN32
    // Restrict staging directory permissions to owner only
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
#endif
    return dir;
}

// Incremental SHA-256: `update()` any number of times over buffers fed to it
// in order, `finalize()` once at the end. Extracted out of what used to be a
// single whole-stream `sha256_stream()` so `do_upload` (below) can feed it
// the EXACT buffer just transmitted, immediately once the server has
// acknowledged it — binding the committed digest to bytes actually sent
// over the wire rather than a second, independent re-read of the file after
// the fact (#P7-003: a second read pass cannot see a write that lands, via
// another handle, in the gap between "chunk sent" and "file re-read").
#ifdef _WIN32
class IncrementalSha256 {
public:
    IncrementalSha256() {
        BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        DWORD result_len = 0;
        BCryptGetProperty(alg_, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len_),
                          sizeof(hash_len_), &result_len, 0);
        BCryptCreateHash(alg_, &hash_, nullptr, 0, nullptr, 0, 0);
    }
    ~IncrementalSha256() {
        if (hash_)
            BCryptDestroyHash(hash_);
        if (alg_)
            BCryptCloseAlgorithmProvider(alg_, 0);
    }
    IncrementalSha256(const IncrementalSha256&) = delete;
    IncrementalSha256& operator=(const IncrementalSha256&) = delete;

    void update(const char* data, std::size_t len) {
        BCryptHashData(hash_, reinterpret_cast<PUCHAR>(const_cast<char*>(data)),
                       static_cast<ULONG>(len), 0);
    }
    std::string finalize() {
        std::vector<UCHAR> digest(hash_len_);
        BCryptFinishHash(hash_, digest.data(), hash_len_, 0);
        std::string hex;
        for (auto b : digest)
            hex += std::format("{:02x}", b);
        return hex;
    }

private:
    BCRYPT_ALG_HANDLE alg_{nullptr};
    BCRYPT_HASH_HANDLE hash_{nullptr};
    DWORD hash_len_{0};
};
#else
class IncrementalSha256 {
public:
    IncrementalSha256() : ctx_(EVP_MD_CTX_new()) { EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr); }
    ~IncrementalSha256() {
        if (ctx_)
            EVP_MD_CTX_free(ctx_);
    }
    IncrementalSha256(const IncrementalSha256&) = delete;
    IncrementalSha256& operator=(const IncrementalSha256&) = delete;

    void update(const char* data, std::size_t len) { EVP_DigestUpdate(ctx_, data, len); }
    std::string finalize() {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        EVP_DigestFinal_ex(ctx_, digest, &len);
        std::string hex;
        for (unsigned i = 0; i < len; ++i)
            hex += std::format("{:02x}", digest[i]);
        return hex;
    }

private:
    EVP_MD_CTX* ctx_;
};
#endif

// SHA-256 over an already-open, positioned ifstream, reading from its
// CURRENT position to EOF — never opens or closes the handle itself.
std::string sha256_stream(std::ifstream& file) {
    IncrementalSha256 hasher;
    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount() > 0)
        hasher.update(buf, static_cast<std::size_t>(file.gcount()));
    return hasher.finalize();
}

std::string sha256_file(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return {};
    return sha256_stream(file);
}

bool is_safe_filename(std::string_view name) {
    if (name.empty() || name.find("..") != std::string_view::npos)
        return false;
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
        try {
            out.port = std::stoi(std::string(port_str));
        } catch (...) {
            out.port = 0;
        }
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
        if (c == ';' || c == '&' || c == '|' || c == '`' || c == '$' || c == '(' || c == ')' ||
            c == '{' || c == '}' || c == '<' || c == '>' || c == '!' || c == '~' || c == '^' ||
            c == '\'' || c == '"' || c == '#' || c == '*' || c == '?' || c == '[' || c == ']' ||
            c == '\n' || c == '\r') {
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
    if (!current.empty())
        result.push_back(std::move(current));
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
        cmdline += L" " + yuzu::win::to_wide(args_str); // (#1681) size-based convert, no NUL
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

    BOOL ok = CreateProcessW(wpath.c_str(),    // application name
                             cmdline.data(),   // command line (mutable)
                             nullptr,          // process security attributes
                             nullptr,          // thread security attributes
                             TRUE,             // inherit handles
                             CREATE_NO_WINDOW, // creation flags — no console window
                             nullptr,          // environment
                             nullptr,          // current directory
                             &si,              // startup info
                             &pi               // process info
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
    for (const auto& a : args)
        argv.push_back(a.c_str());
    argv.push_back(nullptr);

    // Create pipe for stdout capture
    //
    // BR-001: hold the process-wide fork lock across [pipe()..fork()] --
    // macOS/BSD has no pipe2(), so an unrelated thread's fork() landing in
    // this window could inherit these still-inheritable fds. Released in
    // the PARENT right after fork() returns; the child inherits it locked
    // and never touches it (see fork_lock.hpp's contract).
    std::unique_lock<std::mutex> fork_pipe_lock(yuzu::agent::global_fork_lock());

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        output = "failed to create pipe";
        return -1;
    }

    // Fail closed: fork_lock.hpp's release precondition requires CLOEXEC on
    // both pipe ends before the lock is released, so a concurrent locked
    // launcher forking in the unlock->close window can never inherit a live,
    // non-CLOEXEC write end. A failed fcntl here is treated the same as a
    // failed pipe() above rather than silently forking with a leaky fd.
    if (fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) == -1 ||
        fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        output = "failed to set pipe close-on-exec";
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

    // Parent: fork() has returned and this is not the child branch --
    // release the fork lock now (see fork_lock.hpp's contract).
    fork_pipe_lock.unlock();

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

// ── ABI4 per-OS capability declaration (#2204) ──────────────────────────────
//
// `rung` is the ADR-3002 ACQUISITION rung (docs/adr/3002-acquisition-ladder.md:66-73):
// 1 = native OS interface (zero subprocesses), 2 = argv via a runner (no
// shell), 3 = shell/interpreter payload. One row per `actions()` entry,
// same order, same names — capmatrix-gen hard-errors on any mismatch.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "stage",
        // httplib download over a socket this plugin opens itself — zero
        // subprocesses, rung 1 on every OS. HTTPS is a build-time REQUIRED
        // OpenSSL dependency on Linux/macOS (content_dist/meson.build:
        // `dependency('openssl', required: true, ...)`) but only
        // best-effort on Windows (`required: false`) — CPPHTTPLIB_OPENSSL_SUPPORT
        // is conditionally undefined there (see `download_file`'s #else
        // branch above), so Windows is CONSTRAINED, not SUPPORTED.
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "httplib_tls", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "httplib_tls", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "httplib_tls",
         "requires OpenSSL to be found at build time; HTTPS unavailable if absent"},
    },
    {
        /* .action      = */ "execute_staged",
        // Spawns the staged binary directly from a pre-split argv —
        // CreateProcessW on Windows, fork+execvp on POSIX — never a shell
        // (see `safe_execute` above): rung 2 on every OS.
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "fork_execvp", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "fork_execvp", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "createprocessw", nullptr},
    },
    {
        /* .action      = */ "list_staged",
        // std::filesystem directory iteration — in-process, rung 1.
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
    },
    {
        /* .action      = */ "cleanup",
        // std::filesystem removal — in-process, rung 1.
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "std_filesystem", nullptr},
    },
    {
        /* .action      = */ "upload_file",
        // Same httplib-socket transport as `stage`, same Windows OpenSSL
        // caveat.
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "httplib_tls", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "httplib_tls", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "httplib_tls",
         "requires OpenSSL to be found at build time; HTTPS unavailable if absent"},
    },
};

} // namespace

class ContentDistPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "content_dist"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Content staging — download, verify, execute, and manage staged files (no "
               "shell-out)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"stage",   "execute_staged", "list_staged",
                                     "cleanup", "upload_file",    nullptr};
        return acts;
    }

    [[nodiscard]] const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    [[nodiscard]] size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        g_ctx = ctx.raw();
        return {};
    }
    void shutdown(yuzu::PluginContext&) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "stage")
            return do_stage(ctx, params);
        if (action == "execute_staged")
            return do_execute(ctx, params);
        if (action == "list_staged")
            return do_list(ctx);
        if (action == "cleanup")
            return do_cleanup(ctx, params);
        if (action == "upload_file")
            return do_upload(ctx, params);
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
            ctx.write_output(
                "error|invalid filename (alphanumeric, dots, hyphens, underscores only)");
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
            ctx.write_output(
                std::format("error|hash mismatch: expected={}, got={}", expected, hash));
            return 1;
        }

        // #808: persist the verified hash in agent KV so `do_execute` has an
        // authoritative source of truth for re-verification. KV lives in a
        // separate SQLite DB outside the staging directory, so an attacker
        // who can swap a staged file (the TOCTOU window) cannot also rewrite
        // its expected hash. Key namespace `staged_hash:<filename>`.
        yuzu::PluginContext pctx{g_ctx};
        if (!pctx.storage_set(std::string{"staged_hash:"} + std::string{filename}, hash)) {
            std::error_code ec;
            fs::remove(dest, ec);
            ctx.write_output("error|failed to persist staged hash to agent KV");
            return 1;
        }

        ctx.write_output("status|ok");
        ctx.write_output(std::format("staged_path|{}", dest.string()));
        return 0;
    }

    int do_execute(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto filename = params.get("filename");
        if (filename.empty()) {
            ctx.write_output("error|missing required parameter: filename");
            return 1;
        }
        if (!is_safe_filename(filename)) {
            ctx.write_output("error|invalid filename");
            return 1;
        }

        auto path = staging_dir() / std::string{filename};
        if (!fs::exists(path)) {
            ctx.write_output(std::format("error|file not staged: {}", filename));
            return 1;
        }

        // #808: hash re-verification is MANDATORY and the expected hash MUST
        // come from agent KV (persisted by `do_stage` at the moment of
        // download verification). The previous design read `expected_hash`
        // from caller-provided params and skipped verification entirely when
        // the param was absent — a local attacker who could write to the
        // staging directory between stage and execute would then run
        // arbitrary code. By sourcing the hash from KV (a separate SQLite
        // DB outside the staging tree) we eliminate both the skip path and
        // the trust-the-caller-hash oracle.
        yuzu::PluginContext pctx{g_ctx};
        auto kv_key = std::string{"staged_hash:"} + std::string{filename};
        auto trusted_hash = pctx.storage_get(kv_key);
        if (trusted_hash.empty()) {
            // No KV entry — either the file was placed in the staging dir by
            // something other than `do_stage`, or KV was wiped. Either way
            // we have no source of truth, so we refuse.
            ctx.write_output(std::format("error|no trusted hash on record for staged file '{}'; "
                                         "stage the file via the `stage` action first",
                                         filename));
            return 1;
        }
        auto actual = sha256_file(path);
        if (actual != trusted_hash) {
            ctx.write_output(
                std::format("error|hash re-verification failed (file tampered post-stage?): "
                            "expected={}, got={}",
                            trusted_hash, actual));
            return 1;
        }
        // Optional caller-provided `expected_hash` is still honoured if
        // present — but only to detect orchestration drift (caller's idea of
        // the hash diverged from what we staged). Failure here is NOT a
        // security event, just a config mismatch.
        auto caller_hash = params.get("expected_hash");
        if (!caller_hash.empty() && std::string{caller_hash} != trusted_hash) {
            ctx.write_output(
                std::format("error|caller-provided expected_hash does not match the hash "
                            "recorded at stage time: caller={}, staged={}",
                            caller_hash, trusted_hash));
            return 1;
        }

        auto args = params.get("args");
        // Validate args to block shell metacharacters
        if (!args.empty() && !is_safe_arg(args)) {
            ctx.write_output(
                "error|args contain forbidden characters (shell metacharacters blocked)");
            return 1;
        }

        std::string output;
        int rc = safe_execute(path, args, output);

        ctx.write_output(std::format("status|{}", rc == 0 ? "ok" : "error"));
        ctx.write_output(std::format("exit_code|{}", rc));
        if (!output.empty())
            ctx.write_output(std::format("output|{}", output));
        return rc;
    }

    int do_list(yuzu::CommandContext& ctx) {
        auto dir = staging_dir();
        std::error_code ec;
        int count = 0;
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (!entry.is_regular_file())
                continue;
            auto size = entry.file_size(ec);
            auto hash = sha256_file(entry.path());
            ctx.write_output(
                std::format("file|{}|{}|{}", entry.path().filename().string(), size, hash));
            ++count;
        }
        ctx.write_output(std::format("count|{}", count));
        return 0;
    }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    // Sends the grant/session credential's DELETE (cancel) so a
    // server-side partial blob is discarded, then surfaces `error_msg`.
    // Never itself an error — a cancel failure is not this command's
    // failure to report, the upload's own failure already is. Only
    // declared when SSLClient exists at all (see `do_upload`'s matching
    // build guard below) — TLS is mandatory for this transport, so there
    // is no non-SSL variant to guard against.
    void abort_upload(httplib::SSLClient& client, const std::string& cancel_path,
                      const std::string& session_header, yuzu::CommandContext& ctx,
                      const std::string& error_msg) {
        httplib::Headers cancel_headers = {{"X-Yuzu-Upload-Session", session_header}};
        client.Delete(cancel_path, cancel_headers);
        ctx.write_output(std::format("error|{}", error_msg));
    }
#endif

    // ", reason=<name>" when present, empty otherwise — pulled out of the
    // several error-message call sites below so none of them has to juggle
    // a mixed string_view/const-char* ternary.
    static std::string describe_reason(std::optional<up::Reason> reason) {
        if (!reason)
            return {};
        return std::string{", reason="} + std::string{up::reason_string(*reason)};
    }

    int do_upload(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto path_str = params.get("path");
        auto grant_id = params.get("grant_id");
        auto grant_secret = params.get("grant_secret");
        if (path_str.empty() || grant_id.empty() || grant_secret.empty()) {
            ctx.write_output(
                "error|missing required parameters: path, grant_id, grant_secret");
            return 1;
        }

        fs::path file_path{std::string{path_str}};
        std::error_code ec;
        if (!fs::exists(file_path, ec) || !fs::is_regular_file(file_path, ec)) {
            ctx.write_output("error|file does not exist or is not a regular file");
            return 1;
        }

        // Canonicalize path to resolve symlinks and prevent traversal
        auto canon = fs::canonical(file_path, ec);
        if (ec) {
            ctx.write_output("error|failed to resolve path");
            return 1;
        }
        file_path = canon;

        // Enforce base_dir restriction if provided
        auto base_dir = params.get("base_dir");
        if (!base_dir.empty()) {
            auto canon_base = fs::canonical(fs::path{std::string{base_dir}}, ec);
            if (ec) {
                ctx.write_output("error|invalid base_dir");
                return 1;
            }
            auto file_str = file_path.string();
            auto base_str = canon_base.string();
            if (file_str.size() < base_str.size() ||
                file_str.compare(0, base_str.size(), base_str) != 0 ||
                (file_str.size() > base_str.size() && file_str[base_str.size()] != '/' &&
                 file_str[base_str.size()] != '\\')) {
                ctx.write_output("error|path is outside allowed base directory");
                return 1;
            }
        }

        std::error_code size_ec;
        const auto file_size = static_cast<std::int64_t>(fs::file_size(file_path, size_ec));
        if (size_ec || file_size <= 0) {
            ctx.write_output("error|failed to determine file size, or file is empty");
            return 1;
        }

        int max_mb = 100;
        auto max_str = params.get("max_size_mb", "100");
        try {
            max_mb = std::stoi(std::string{max_str});
        } catch (...) {}
        if (static_cast<std::uintmax_t>(file_size) > static_cast<std::uintmax_t>(max_mb) * 1024 * 1024) {
            ctx.write_output(
                std::format("error|file too large ({} bytes, max {} MB)", file_size, max_mb));
            return 1;
        }

        // The base URL comes ONLY from the agent's own configured server
        // transport (agent.server_web_url) — this action no longer accepts
        // an operator-supplied URL parameter at all (CC-06), and no request
        // below ever carries a self-declared agent id: identity is entirely
        // a server-side fact tied to the grant. TLS is mandatory —
        // an explicit http:// value is a hard configuration error, never
        // silently used or upgraded; a bare host (no scheme) defaults to
        // https, matching this plugin's pre-existing bare-host convention.
        yuzu::PluginContext pctx{g_ctx};
        auto configured = pctx.get_config("agent.server_web_url");
        if (configured.empty()) {
            ctx.write_output(
                "error|agent.server_web_url is not configured; cannot reach the upload endpoint");
            return 1;
        }
        if (configured.starts_with("http://")) {
            ctx.write_output("error|agent.server_web_url must not be http://; TLS is mandatory");
            return 1;
        }
        std::string url_to_parse = configured.starts_with("https://")
                                       ? std::string{configured}
                                       : ("https://" + std::string{configured});
        ParsedUrl base;
        if (!parse_url(url_to_parse, base) || !base.is_https) {
            ctx.write_output("error|agent.server_web_url is not a valid host or URL");
            return 1;
        }

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
        ctx.write_output("error|HTTPS not supported in this build (OpenSSL not available)");
        return 1;
#else
        httplib::SSLClient client(base.host, base.port);
        client.set_connection_timeout(30);
        client.set_read_timeout(300);
        client.enable_server_certificate_verification(true);

        // The destination is opened EXACTLY ONCE for this upload. Every
        // chunk below reads its bytes via `seekg` on THIS SAME ifstream
        // handle, and the commit hash is accumulated incrementally from the
        // SAME buffer each chunk transmits, the moment the server
        // acknowledges it — never by reopening the file or independently
        // re-reading it through a second pass — so the committed digest
        // can never describe different bytes than were actually streamed
        // to the server (#P7-003).
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            ctx.write_output("error|failed to open file");
            return 1;
        }

        // ── Session open ─────────────────────────────────────────────
        const std::string grant_header = std::string{grant_id} + "." + std::string{grant_secret};
        httplib::Headers open_headers = {{"X-Yuzu-Upload-Grant", grant_header}};

        std::optional<up::SessionOpenResponse> session;
        for (int attempt = 1;; ++attempt) {
            auto open_res = client.Post("/api/v1/uploads", open_headers);
            const int status = open_res ? open_res->status : 0;
            if (open_res && status == 201) {
                session = up::parse_session_open_response(open_res->body);
                if (!session) {
                    ctx.write_output("error|malformed session-open response from server");
                    return 1;
                }
                break;
            }
            std::optional<up::Reason> reason;
            if (open_res)
                reason = up::parse_error_envelope(open_res->body).reason;
            auto decision = up::decide_next_action(status, reason, attempt);
            if (decision.action != up::UploadDecision::kRetry) {
                ctx.write_output(std::format("error|failed to open upload session (HTTP {}{})",
                                             status, describe_reason(reason)));
                return 1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(decision.backoff_ms));
        }

        if (session->chunk_max_bytes <= 0) {
            ctx.write_output("error|server returned an invalid chunk_max_bytes");
            return 1;
        }

        const std::string session_header = session->upload_id + "." + session->session_secret;
        const std::string chunk_path = "/api/v1/uploads/" + session->upload_id + "/chunk";
        const std::string commit_path = "/api/v1/uploads/" + session->upload_id + "/commit";
        const std::string cancel_path = "/api/v1/uploads/" + session->upload_id;

        ctx.report_progress(5);

        // ── Chunk streaming ──────────────────────────────────────────
        // The commit digest is built INCREMENTALLY from the exact buffer
        // just transmitted, fed to `hasher` the moment the server
        // acknowledges it (never from a later, independent re-read — see
        // the RAII-handle comment above, #P7-003). The one unavoidable
        // exception is a RESUMED session's already-uploaded prefix
        // (`session->offset > 0`, accepted in an earlier process's run):
        // those bytes were never in THIS process's memory, so they are
        // read once, up front, via the SAME open handle everything else
        // below uses.
        IncrementalSha256 hasher;
        if (session->offset > 0) {
            file.clear();
            file.seekg(0, std::ios::beg);
            std::vector<char> prefix_buf(64 * 1024);
            std::int64_t remaining = session->offset;
            while (remaining > 0) {
                const auto want = static_cast<std::streamsize>(
                    std::min<std::int64_t>(remaining, static_cast<std::int64_t>(prefix_buf.size())));
                file.read(prefix_buf.data(), want);
                if (file.gcount() != want) {
                    ctx.write_output("error|failed to read local file while hashing an "
                                     "already-uploaded prefix");
                    return 1;
                }
                hasher.update(prefix_buf.data(), static_cast<std::size_t>(want));
                remaining -= want;
            }
        }

        std::int64_t offset = session->offset;
        std::int64_t last_progress_offset = -1;
        int attempt = 1;
        std::vector<char> buf;

        while (offset < file_size) {
            if (offset > last_progress_offset) {
                last_progress_offset = offset;
                attempt = 1;
            }

            auto spec = up::plan_next_chunk(offset, file_size, session->chunk_max_bytes);
            if (!spec) {
                abort_upload(client, cancel_path, session_header, ctx,
                            "internal chunk-planning error");
                return 1;
            }
            const auto chunk_len = spec->end - spec->start + 1;
            buf.resize(static_cast<std::size_t>(chunk_len));
            file.clear();
            file.seekg(spec->start, std::ios::beg);
            file.read(buf.data(), static_cast<std::streamsize>(chunk_len));
            if (file.gcount() != static_cast<std::streamsize>(chunk_len)) {
                abort_upload(client, cancel_path, session_header, ctx,
                            "failed to read local file while streaming");
                return 1;
            }

            httplib::Headers chunk_headers = {
                {"X-Yuzu-Upload-Session", session_header},
                {"Content-Range", std::format("bytes {}-{}/{}", spec->start, spec->end, spec->total)},
            };
            auto res = client.Put(chunk_path, chunk_headers, std::string(buf.data(), buf.size()),
                                  "application/octet-stream");
            const int status = res ? res->status : 0;

            if (res && status == 200) {
                auto ack = up::parse_chunk_ack_offset(res->body);
                // The only valid ack is EXACTLY `spec->end + 1` — the agent
                // already knows what a successful write of THIS chunk must
                // produce, so a missing or disagreeing offset is a
                // malformed/inconsistent response, not new state to adopt
                // (#P7-004).
                auto validated = up::validate_chunk_ack(ack, spec->end + 1, file_size);
                if (!validated) {
                    abort_upload(client, cancel_path, session_header, ctx,
                                "server returned a missing or inconsistent chunk offset "
                                "acknowledgement");
                    return 1;
                }
                // Hash the SAME buffer just transmitted, now that the
                // server has confirmed receipt of exactly this range.
                hasher.update(buf.data(), buf.size());
                offset = *validated;
                ctx.report_progress(
                    5 + static_cast<int>(offset * 90 / file_size)); // 5..95 while streaming
                continue;
            }

            std::optional<up::Reason> reason;
            if (res)
                reason = up::parse_error_envelope(res->body).reason;
            auto decision = up::decide_next_action(status, reason, attempt);
            switch (decision.action) {
            case up::UploadDecision::kResync: {
                auto authoritative = res ? up::parse_error_envelope(res->body).offset
                                         : std::nullopt;
                auto resynced = authoritative
                                    ? up::reconcile_resume_offset(*authoritative, file_size)
                                    : std::nullopt;
                if (!resynced) {
                    abort_upload(client, cancel_path, session_header, ctx,
                                "server reported offset_mismatch without a usable offset");
                    return 1;
                }
                if (*resynced <= offset) {
                    // No forward progress — without a bounded budget here a
                    // server that keeps handing back a non-advancing
                    // offset would drive an unbounded resend loop
                    // (#P7-006). Reuses the SAME attempt/backoff budget as
                    // an ordinary retry; a resync that DOES advance resets
                    // it via the `offset > last_progress_offset` check at
                    // the top of the loop, same as any other progress.
                    if (up::attempts_exhausted(attempt)) {
                        abort_upload(client, cancel_path, session_header, ctx,
                                    "offset_mismatch resync made no forward progress after "
                                    "repeated attempts");
                        return 1;
                    }
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(up::backoff_delay_ms(attempt)));
                    ++attempt;
                }
                offset = *resynced;
                continue;
            }
            case up::UploadDecision::kRetry:
                ++attempt;
                std::this_thread::sleep_for(std::chrono::milliseconds(decision.backoff_ms));
                continue;
            case up::UploadDecision::kAbort:
                abort_upload(client, cancel_path, session_header, ctx,
                            std::format("chunk upload failed (HTTP {}{})", status,
                                        describe_reason(reason)));
                return 1;
            }
        }

        auto computed_hash = hasher.finalize();
        if (computed_hash.empty()) {
            abort_upload(client, cancel_path, session_header, ctx,
                        "failed to compute upload hash");
            return 1;
        }

        // ── Commit ───────────────────────────────────────────────────
        // Bounded retry loop mirroring session-open's, driven by the SAME
        // `decide_next_action` (#P7-002: a transient commit failure used to
        // cancel the upload outright instead of honouring the retry
        // policy). A `session_terminal` reason on commit specifically, or a
        // pure connection-level/unreasoned failure once the retry budget is
        // exhausted, is outcome-AMBIGUOUS: the server may already have
        // committed THIS exact upload from an earlier attempt whose
        // response never reached the agent (`file_retrieval_routes.cpp`'s
        // commit handler races itself by design — a concurrent winner
        // reports `session_terminal` to the loser). The status route
        // answers 200 with the current state even for a terminal session,
        // so that ambiguity is resolved there BEFORE declaring failure or
        // sending a cancel that would otherwise be pointless or misleading.
        httplib::Headers commit_headers = {{"X-Yuzu-Upload-Session", session_header}};
        const std::string commit_body = "{\"sha256\":\"" + computed_hash + "\"}";

        std::optional<up::CommitResponse> commit_result;
        for (int commit_attempt = 1;; ++commit_attempt) {
            auto commit_res =
                client.Post(commit_path, commit_headers, commit_body, "application/json");
            const int commit_status = commit_res ? commit_res->status : 0;
            if (commit_res && commit_status == 200) {
                commit_result = up::parse_commit_response(commit_res->body);
                if (!commit_result) {
                    ctx.write_output("error|malformed commit response from server");
                    return 1;
                }
                break;
            }

            std::optional<up::Reason> reason;
            if (commit_res)
                reason = up::parse_error_envelope(commit_res->body).reason;
            auto decision = up::decide_next_action(commit_status, reason, commit_attempt);

            const bool ambiguous = reason == up::Reason::kSessionTerminal ||
                                   (decision.action != up::UploadDecision::kRetry &&
                                    up::is_transient_no_reason(commit_status, reason));
            if (ambiguous) {
                auto status_res = client.Get(
                    cancel_path, httplib::Headers{{"X-Yuzu-Upload-Session", session_header}});
                if (status_res && status_res->status == 200) {
                    auto st = up::parse_status_response(status_res->body);
                    if (st && st->state == "committed") {
                        // Reported response values are our own locally
                        // transmitted state — the server's commit ONLY
                        // succeeds with the sha256 this exact run posted
                        // (`upload_grant::verify_commit`), so these are the
                        // values that committed, whichever attempt won.
                        commit_result = up::CommitResponse{"committed", file_size, computed_hash};
                        break;
                    }
                }
            }

            if (decision.action == up::UploadDecision::kRetry) {
                std::this_thread::sleep_for(std::chrono::milliseconds(decision.backoff_ms));
                continue;
            }

            abort_upload(client, cancel_path, session_header, ctx,
                        std::format("commit failed (HTTP {}{})", commit_status,
                                    describe_reason(reason)));
            return 1;
        }

        // The server's own reported size/hash must agree with what this
        // run computed and transmitted — a 200 naming different metadata
        // is a server-contract violation, not a result to trust (#P7-009).
        if (!up::commit_matches(*commit_result, file_size, computed_hash)) {
            ctx.write_output(std::format(
                "error|commit response does not match the uploaded file (expected size={} "
                "sha256={}, server reported size={} sha256={})",
                file_size, computed_hash, commit_result->actual_size, commit_result->sha256));
            return 1;
        }

        ctx.report_progress(100);
        ctx.write_output("status|ok");
        ctx.write_output(std::format("sha256|{}", commit_result->sha256));
        ctx.write_output(std::format("size|{}", commit_result->actual_size));
        ctx.write_output(std::format("upload_id|{}", session->upload_id));
        return 0;
#endif
    }

    int do_cleanup(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto hours_str = params.get("hours");
        int hours = 24;
        if (!hours_str.empty()) {
            try {
                hours = std::stoi(std::string{hours_str});
            } catch (...) {}
        }

        auto dir = staging_dir();
        auto cutoff = fs::file_time_type::clock::now() - std::chrono::hours(hours);
        std::error_code ec;
        int removed = 0;
        yuzu::PluginContext pctx{g_ctx};
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (entry.is_regular_file() && entry.last_write_time(ec) < cutoff) {
                auto fname = entry.path().filename().string();
                fs::remove(entry.path(), ec);
                // #808: also evict the staged-hash KV entry so an entry
                // can't outlive the file it describes (would leak storage
                // and confuse a future `do_execute` that fails on
                // "file not staged" rather than the more useful
                // "no trusted hash on record" message — but the file
                // doesn't exist anyway, so either is correct).
                pctx.storage_delete(std::string{"staged_hash:"} + fname);
                ++removed;
            }
        }
        ctx.write_output(std::format("removed|{}", removed));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(ContentDistPlugin)
