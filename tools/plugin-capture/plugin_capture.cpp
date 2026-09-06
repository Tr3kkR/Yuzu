/**
 * plugin-capture — run a built plugin's actions through the agent's real
 * LocalDispatcher and write a sample-output file for its README
 * (docs/plugin-readme-standard.md, rule 5).
 *
 *   plugin-capture <plugin.{dylib,so,dll}> --os <windows|linux|macos>
 *                  --host-class <bare-metal|vm|container>
 *                  --action <name> [--param k=v ...] [--action <name> ...]
 *                  [--os-version <text>] [--privilege <text>] [--out <file>]
 *
 * Output (stdout, or --out):
 *
 *   captured: <os> <os-version> · <host-class> · <YYYY-MM-DD> · <privilege> · leg-hash pending
 *   == action=<name> [key=value ...]
 *   <rows exactly as the plugin wrote them>
 *   [result_status] <STATUS> / <COMPLETENESS> / <provenance>
 *
 * The leg-hash is filled in afterwards by `plugin_doc_gen.py --stamp <plugin> <os>`
 * so the hash is computed in exactly one place. Nothing here is hand-typed:
 * the rows are what `yuzu::agent::LocalDispatcher::run` captured from the
 * plugin's own `write_output` calls, and the status line is the CC-07 typed
 * result the plugin reported through `set_result_status`.
 *
 * `--param` binds to the most recent `--action`. A value containing spaces
 * is written double-quoted on the action line so a sample stays reproducible.
 */

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include <unistd.h>
#endif

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
    char buf[16];
    std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm);
    return buf;
}

std::string default_privilege() {
#if defined(_WIN32)
    return "-";
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
                 " --action <name> [--param k=v ...] [--action <name> ...]"
                 " [--os-version <text>] [--privilege <text>] [--out <file>]\n";
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) return usage(argv[0]);
    std::string lib = argv[1];
    std::string os_name, host_class, os_version = "-", privilege = default_privilege(), out_path;
    std::vector<ActionSpec> actions;
    for (int i = 2; i < argc; ++i) {
        std::string_view a = argv[i];
        auto need = [&](const char* flag) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << "plugin-capture: " << flag << " requires a value\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--os") os_name = need("--os");
        else if (a == "--host-class") host_class = need("--host-class");
        else if (a == "--os-version") os_version = need("--os-version");
        else if (a == "--privilege") privilege = need("--privilege");
        else if (a == "--out") out_path = need("--out");
        else if (a == "--action") actions.push_back({need("--action"), {}});
        else if (a == "--param") {
            std::string kv = need("--param");
            auto eq = kv.find('=');
            if (actions.empty() || eq == std::string::npos) {
                std::cerr << "plugin-capture: --param k=v must follow an --action\n";
                return 2;
            }
            actions.back().params.emplace_back(kv.substr(0, eq), kv.substr(eq + 1));
        } else {
            std::cerr << "plugin-capture: unknown argument " << a << "\n";
            return usage(argv[0]);
        }
    }
    if (os_name.empty() || host_class.empty() || actions.empty()) return usage(argv[0]);
    if (os_name != "windows" && os_name != "linux" && os_name != "macos") {
        std::cerr << "plugin-capture: --os must be windows, linux or macos\n";
        return 2;
    }

    auto loaded = yuzu::agent::PluginHandle::load(lib);
    if (!loaded) {
        std::cerr << "plugin-capture: failed to load " << lib << "\n";
        return 1;
    }
    const YuzuPluginDescriptor* desc = loaded->descriptor();
    if (!desc) {
        std::cerr << "plugin-capture: " << lib << " has no descriptor\n";
        return 1;
    }

    std::ostringstream out;
    out << "captured: " << os_name << ' ' << os_version << " · " << host_class << " · " << today()
        << " · " << privilege << " · leg-hash pending\n";

    yuzu::agent::LocalDispatcher dispatcher;
    int worst_rc = 0;
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
            worst_rc = result.rc;
        }
        out << '\n';
    }

    if (out_path.empty()) {
        std::cout << out.str();
    } else {
        std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
        if (!f) {
            std::cerr << "plugin-capture: cannot write " << out_path << "\n";
            return 1;
        }
        f << out.str();
    }
    // A non-zero plugin rc is still a valid capture (the row says what
    // happened); report it on stderr so a scripted run can notice.
    if (worst_rc != 0) std::cerr << "plugin-capture: one or more actions returned rc " << worst_rc << "\n";
    return 0;
}
