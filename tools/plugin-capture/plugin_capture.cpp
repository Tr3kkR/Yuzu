/**
 * plugin-capture — run a built plugin's actions through the agent's real
 * LocalDispatcher and write a sample-output file for its README
 * (docs/plugin-readme-standard.md, rule 5).
 *
 *   plugin-capture <plugin.{dylib,so,dll}> --os <windows|linux|macos>
 *                  --host-class <bare-metal|vm|container>
 *                  --action <name> [--param k=v ...] [--action <name> ...]
 *                  [--config k=v ...] [--os-version <text>] [--privilege <text>]
 *                  [--out <file>]
 *
 * Output (stdout, or --out):
 *
 *   captured: <os> <os-version> · <host-class> · <YYYY-MM-DD> · <privilege> · leg-hash pending
 *   == action=<name> [key=value ...]
 *   <rows exactly as the plugin wrote them>
 *   [truncated] ...            (only when the capture hit the dispatcher byte cap)
 *   [result_status] <STATUS> / <COMPLETENESS> / <provenance>
 *   [rc] <n>                   (only when the plugin returned non-zero)
 *
 * The leg-hash is filled in afterwards by `plugin_doc_gen.py --stamp <plugin> <os>`
 * so the hash is computed in exactly one place. Nothing here is hand-typed:
 * the rows are what `yuzu::agent::LocalDispatcher::run` captured from the
 * plugin's own `write_output` calls, and the status line is the CC-07 typed
 * result the plugin reported through `set_result_status`.
 *
 * Lifecycle: the plugin's `init` runs once before the first action with a
 * real plugin context (`yuzu::agent::StandalonePluginContext` — the
 * configuration map from `--config k=v`, no KV store, no trigger engine),
 * and `shutdown` runs after the last, the same order the agent host uses.
 * A plugin whose init needs the agent's KV store or the server (tags, tar,
 * content_dist, …) therefore fails closed here exactly as it would under a
 * host without those services; such a leg is recorded with a
 * `[not captured] agent-context: …` line instead (rule 5).
 *
 * `--param` binds to the most recent `--action`. A value containing spaces
 * is written double-quoted on the action line so a sample stays reproducible.
 *
 * The agent core's logger (the plugin loader's "Loaded plugin …" line, a
 * plugin's own spdlog warnings) is routed to stderr before anything is
 * loaded, so a capture written to stdout is exactly the sample and nothing
 * else; `--out` writes the same bytes to a file. Both are written in binary
 * mode (LF line endings on every OS) and are checked after the write.
 *
 * Exit status: 0 = the sample was written in full (a non-zero plugin rc is
 * still a valid capture — the `[rc]` line says what happened and stderr
 * repeats it); 1 = the plugin could not be loaded, its init refused, or the
 * output could not be written in full; 2 = usage error.
 */

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/spdlog.h>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

namespace {

struct ActionSpec {
    std::string name;
    std::vector<std::pair<std::string, std::string>> params;
};

const char* status_name(YuzuResultStatus s) {
    switch (s) {
    case YUZU_RESULT_STATUS_OK: return "OK";
    case YUZU_RESULT_STATUS_UNAVAILABLE: return "UNAVAILABLE";
    case YUZU_RESULT_STATUS_PERMISSION_DENIED: return "PERMISSION_DENIED";
    case YUZU_RESULT_STATUS_CONSTRAINED: return "CONSTRAINED";
    case YUZU_RESULT_STATUS_UNDECLARED: break;
    }
    return "UNDECLARED";
}

const char* completeness_name(YuzuResultCompleteness c) {
    switch (c) {
    case YUZU_RESULT_COMPLETENESS_FULL: return "FULL";
    case YUZU_RESULT_COMPLETENESS_PARTIAL: return "PARTIAL";
    case YUZU_RESULT_COMPLETENESS_UNKNOWN: break;
    }
    return "UNKNOWN";
}

std::string today() {
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &now);
#else
    localtime_r(&now, &tm);
#endif
    char buf[16]{};
    std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm);
    return buf;
}

#if defined(_WIN32)
std::string utf8_from_wide(const wchar_t* ws) {
    const int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<std::size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, out.data(), n, nullptr, nullptr);
    return out;
}
#endif

// The measured privilege the stamp records when --privilege is not given:
// the effective uid on POSIX; the token's user and elevation state on Windows.
std::string default_privilege() {
#if defined(_WIN32)
    std::string user = "-";
    wchar_t name[256]{};
    DWORD len = static_cast<DWORD>(std::size(name));
    if (GetUserNameW(name, &len)) user = utf8_from_wide(name);
    std::string elevation = "elevation unknown";
    HANDLE raw = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) {
        TOKEN_ELEVATION te{};
        DWORD got = 0;
        if (GetTokenInformation(raw, TokenElevation, &te, sizeof te, &got))
            elevation = te.TokenIsElevated ? "elevated" : "not elevated";
        CloseHandle(raw);
    }
    return user + " (" + elevation + ")";
#else
    return "euid " + std::to_string(static_cast<long>(geteuid()));
#endif
}

std::string quote_if_needed(const std::string& v) {
    if (v.find(' ') == std::string::npos && !v.empty()) return v;
    return "\"" + v + "\"";
}

int usage(const char* argv0) {
    std::cerr << "usage: " << argv0
              << " <plugin-library> --os <windows|linux|macos> --host-class <bare-metal|vm|container>"
                 " --action <name> [--param k=v ...] [--action <name> ...] [--config k=v ...]"
                 " [--os-version <text>] [--privilege <text>] [--out <file>]\n";
    return 2;
}

bool split_kv(const std::string& kv, std::string& k, std::string& v) {
    const auto eq = kv.find('=');
    if (eq == std::string::npos || eq == 0) return false;
    k = kv.substr(0, eq);
    v = kv.substr(eq + 1);
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) return usage(argv[0]);
    std::string lib = argv[1];
    std::string os_name, host_class, os_version = "-", privilege = default_privilege(), out_path;
    std::vector<ActionSpec> actions;
    std::unordered_map<std::string, std::string> config;
    for (int i = 2; i < argc; ++i) {
        const std::string_view flag = argv[i];
        const bool known = flag == "--os" || flag == "--host-class" || flag == "--os-version" ||
                           flag == "--privilege" || flag == "--out" || flag == "--action" ||
                           flag == "--param" || flag == "--config";
        if (!known) {
            std::cerr << "plugin-capture: unknown argument " << flag << "\n";
            return usage(argv[0]);
        }
        if (i + 1 >= argc) {
            std::cerr << "plugin-capture: " << flag << " requires a value\n";
            return 2;
        }
        const std::string value = argv[++i];
        if (flag == "--os") os_name = value;
        else if (flag == "--host-class") host_class = value;
        else if (flag == "--os-version") os_version = value;
        else if (flag == "--privilege") privilege = value;
        else if (flag == "--out") out_path = value;
        else if (flag == "--action") actions.push_back({value, {}});
        else {
            std::string k, v;
            if (!split_kv(value, k, v)) {
                std::cerr << "plugin-capture: " << flag << " takes key=value, got " << value << "\n";
                return 2;
            }
            if (flag == "--config") {
                config[k] = v;
            } else if (actions.empty()) {
                std::cerr << "plugin-capture: --param k=v must follow an --action\n";
                return 2;
            } else {
                actions.back().params.emplace_back(std::move(k), std::move(v));
            }
        }
    }
    if (os_name.empty() || host_class.empty() || actions.empty()) return usage(argv[0]);
    if (os_name != "windows" && os_name != "linux" && os_name != "macos") {
        std::cerr << "plugin-capture: --os must be windows, linux or macos\n";
        return 2;
    }

    // stdout is the sample; every log line goes to stderr (see the header).
    spdlog::set_default_logger(spdlog::stderr_logger_mt("plugin-capture"));

    auto loaded = yuzu::agent::PluginHandle::load(lib);
    if (!loaded) {
        std::cerr << "plugin-capture: failed to load " << lib << ": " << loaded.error().reason
                  << "\n";
        return 1;
    }
    const YuzuPluginDescriptor* desc = loaded->descriptor();
    if (!desc) {
        std::cerr << "plugin-capture: " << lib << " has no descriptor\n";
        return 1;
    }

    // Lifecycle as the agent host runs it: init once with a real context,
    // every dispatch, then shutdown. `ctx` is declared after `loaded` so the
    // library outlives the context, and every dispatch below happens between
    // init and shutdown.
    yuzu::agent::StandalonePluginContext ctx(desc->name ? desc->name : "", std::move(config));
    if (desc->init) {
        const int rc = desc->init(ctx.get());
        if (rc != 0) {
            std::cerr << "plugin-capture: " << lib << ": init returned " << rc
                      << " — the plugin refused to start under this host (missing agent context?);"
                         " record the leg as `[not captured] agent-context: <reason>` instead\n";
            return 1;
        }
    }

    std::ostringstream out;
    out << "captured: " << os_name << ' ' << os_version << " · " << host_class << " · " << today()
        << " · " << privilege << " · leg-hash pending\n";

    yuzu::agent::LocalDispatcher dispatcher;
    int last_nonzero_rc = 0;
    for (const auto& spec : actions) {
        std::vector<YuzuParam> params;
        params.reserve(spec.params.size());
        for (const auto& [k, v] : spec.params) params.push_back(YuzuParam{k.c_str(), v.c_str()});
        auto result = dispatcher.run(desc, spec.name, std::span<const YuzuParam>(params));

        out << "== action=" << spec.name;
        for (const auto& [k, v] : spec.params) out << ' ' << k << '=' << quote_if_needed(v);
        out << '\n';
        if (!result.captured.empty()) {
            out << result.captured;
            if (result.captured.back() != '\n') out << '\n';
        }
        if (result.truncated) out << "[truncated] capture hit the LocalDispatcher byte cap\n";
        out << "[result_status] " << status_name(result.result_status) << " / "
            << completeness_name(result.result_completeness) << " / " << result.result_provenance
            << '\n';
        if (result.rc != 0) {
            out << "[rc] " << result.rc << '\n';
            last_nonzero_rc = result.rc;
        }
        out << '\n';
    }
    if (desc->shutdown) desc->shutdown(ctx.get());

    // A short write (disk full, closed pipe) must never leave a partial sample
    // behind with a zero exit: the parser would accept the prefix as a whole
    // capture. Flush, then check the stream.
    const std::string sample = out.str();
    if (out_path.empty()) {
#if defined(_WIN32)
        _setmode(_fileno(stdout), _O_BINARY); // LF, not CRLF, like --out
#endif
        std::cout << sample;
        std::cout.flush();
        if (!std::cout) {
            std::cerr << "plugin-capture: writing the sample to stdout failed\n";
            return 1;
        }
    } else {
        std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
        if (!f) {
            std::cerr << "plugin-capture: cannot open " << out_path << " for writing\n";
            return 1;
        }
        f << sample;
        f.flush();
        if (!f) {
            std::cerr << "plugin-capture: writing " << out_path << " failed — the file is incomplete\n";
            return 1;
        }
    }
    // A non-zero plugin rc is still a valid capture (the row says what
    // happened); report it on stderr so a scripted run can notice.
    if (last_nonzero_rc != 0)
        std::cerr << "plugin-capture: an action returned rc " << last_nonzero_rc
                  << " (see its [rc] line)\n";
    return 0;
}
