/**
 * capmatrix-gen — #2204 capability-matrix generator (PR1.1).
 *
 * Host tool: dlopens each built plugin shared library and reads its
 * YuzuPluginDescriptor (ABI4, sdk/include/yuzu/plugin.h) to emit a
 * deterministic Markdown fragment describing the per-action, per-OS
 * capability declarations, plus the RATCHET list of plugins that haven't
 * adopted the descriptor yet.
 *
 * Loading mirrors tests/unit/test_new_plugins.cpp's load_plugin(): dlopen +
 * symbol lookup only — init() is NEVER called, so this tool cannot trip a
 * plugin's real startup side effects (KV storage, trigger registration,
 * etc.). It only ever reads the static descriptor.
 *
 * Usage: capmatrix-gen --out <path> <plugin.so> [<plugin.so> ...]
 *
 * Every path given on the command line MUST exist and MUST export
 * yuzu_plugin_descriptor() returning non-null — a missing or unloadable
 * plugin is a hard error, never silently skipped. The whole point of the
 * drift gate (scripts/ci/check-capability-matrix.sh) is to prove the
 * committed matrix reflects what actually got built; silently omitting a
 * plugin that failed to load would let the matrix pass while lying about
 * that plugin's absence.
 */

#include <yuzu/plugin.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace fs = std::filesystem;

namespace {

std::string_view support_name(YuzuSupportLevel level) {
    switch (level) {
    case YUZU_SUPPORT_SUPPORTED:
        return "supported";
    case YUZU_SUPPORT_CONSTRAINED:
        return "constrained";
    case YUZU_SUPPORT_PLANNED:
        return "planned";
    case YUZU_SUPPORT_UNSUPPORTED:
        return "unsupported";
    case YUZU_SUPPORT_UNDECLARED:
        break;
    }
    return "undeclared";
}

/// RAII wrapper around a dlopen/LoadLibrary handle plus the descriptor it
/// yielded. Read-only: init() is never invoked.
struct LoadedPlugin {
    void* handle{nullptr};
    const YuzuPluginDescriptor* desc{nullptr};
    std::string path;

    LoadedPlugin() = default;
    LoadedPlugin(const LoadedPlugin&) = delete;
    LoadedPlugin& operator=(const LoadedPlugin&) = delete;
    LoadedPlugin(LoadedPlugin&& o) noexcept
        : handle(o.handle), desc(o.desc), path(std::move(o.path)) {
        o.handle = nullptr;
        o.desc = nullptr;
    }
    LoadedPlugin& operator=(LoadedPlugin&& o) noexcept {
        if (this != &o) {
            close();
            handle = o.handle;
            desc = o.desc;
            path = std::move(o.path);
            o.handle = nullptr;
            o.desc = nullptr;
        }
        return *this;
    }
    ~LoadedPlugin() { close(); }

private:
    void close() {
        if (!handle)
            return;
#ifdef _WIN32
        FreeLibrary(static_cast<HMODULE>(handle));
#else
        dlclose(handle);
#endif
        handle = nullptr;
    }
};

/// Mirrors tests/unit/test_new_plugins.cpp's load_plugin() dlopen + symbol
/// lookup exactly (same failure modes), applied to an explicit path instead
/// of a search-dir scan — the CI step passes exact BUILDDIR/plugin paths.
bool load(const fs::path& so_path, LoadedPlugin& out) {
    std::error_code ec;
    if (!fs::exists(so_path, ec) || ec) {
        std::cerr << "capmatrix-gen: plugin artifact missing: " << so_path.string() << "\n";
        return false;
    }

#ifdef _WIN32
    auto abs_path = fs::absolute(so_path);
    HMODULE hmod = LoadLibraryW(abs_path.wstring().c_str());
    if (!hmod) {
        std::cerr << "capmatrix-gen: LoadLibrary failed for " << so_path.string()
                  << " (error " << GetLastError() << ")\n";
        return false;
    }
    out.handle = static_cast<void*>(hmod);
    auto fn = reinterpret_cast<yuzu_plugin_descriptor_fn>(
        GetProcAddress(hmod, "yuzu_plugin_descriptor"));
#else
    void* h = dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        std::cerr << "capmatrix-gen: dlopen failed for " << so_path.string() << ": " << dlerror()
                  << "\n";
        return false;
    }
    out.handle = h;
    auto fn = reinterpret_cast<yuzu_plugin_descriptor_fn>(dlsym(h, "yuzu_plugin_descriptor"));
#endif

    if (!fn) {
        std::cerr << "capmatrix-gen: missing export 'yuzu_plugin_descriptor' in "
                  << so_path.string() << "\n";
        return false;
    }
    out.desc = fn();
    if (!out.desc) {
        std::cerr << "capmatrix-gen: yuzu_plugin_descriptor() returned null for "
                  << so_path.string() << "\n";
        return false;
    }
    out.path = so_path.string();
    return true;
}

std::string escape_cell(std::string_view s) {
    // Markdown table cells: escape pipes and backslashes so a mechanism/
    // fallback string containing one cannot break the table structure or
    // its own escape, and normalize CR/LF to <br> so a multi-line note
    // can't inject an extra, malformed table row.
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '\\') {
            out += "\\\\";
        } else if (c == '|') {
            out += "\\|";
        } else if (c == '\r') {
            // Skip a lone '\r' or the '\r' of a "\r\n" pair — the '\n'
            // (or the end of string) already emits the <br>.
            if (i + 1 >= s.size() || s[i + 1] != '\n')
                out += "<br>";
        } else if (c == '\n') {
            out += "<br>";
        } else {
            out += c;
        }
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    std::string out_path;
    std::vector<std::string> plugin_paths;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--out" && i + 1 < argc) {
            out_path = argv[++i];
        } else if (arg == "--out") {
            std::cerr << "capmatrix-gen: --out requires a path argument\n";
            return 2;
        } else {
            plugin_paths.push_back(std::move(arg));
        }
    }

    if (out_path.empty() || plugin_paths.empty()) {
        std::cerr << "usage: capmatrix-gen --out <path> <plugin.so> [<plugin.so> ...]\n";
        return 2;
    }

    // Deterministic invocation order regardless of how the caller listed
    // paths on the command line.
    std::sort(plugin_paths.begin(), plugin_paths.end());

    std::vector<LoadedPlugin> plugins;
    plugins.reserve(plugin_paths.size());
    bool any_failed = false;
    for (const auto& p : plugin_paths) {
        LoadedPlugin lp;
        if (!load(p, lp)) {
            any_failed = true;
            continue;
        }
        plugins.push_back(std::move(lp));
    }
    if (any_failed) {
        // Never emit a partial/misleading matrix — a plugin that failed to
        // load is exactly the case the drift gate exists to catch.
        std::cerr << "capmatrix-gen: one or more plugin artifacts failed to load — aborting\n";
        return 1;
    }

    // Stable, name-ordered table (declared plugin name, not path).
    std::sort(plugins.begin(), plugins.end(), [](const LoadedPlugin& a, const LoadedPlugin& b) {
        std::string_view an = a.desc->name ? a.desc->name : "";
        std::string_view bn = b.desc->name ? b.desc->name : "";
        return an < bn;
    });

    std::ostringstream out;
    out << "<!-- BEGIN GENERATED: capmatrix-gen (#2204) — do not hand-edit; regenerate with\n"
           "     tools/capmatrix-gen, verified by scripts/ci/check-capability-matrix.sh -->\n";
    out << "| Plugin | Action | OS | Support | Rung | Mechanism | Fallback |\n";
    out << "|---|---|---|---|---|---|---|\n";

    std::vector<std::string> undeclared;
    for (const auto& lp : plugins) {
        const auto* d = lp.desc;
        const std::string name = d->name ? d->name : "(unnamed)";

        if (d->abi_version < 4 || d->action_descriptor_count == 0 || d->action_descriptors == nullptr) {
            undeclared.push_back(name);
            continue;
        }

        struct LegRow {
            const char* os;
            const YuzuOsLeg& leg;
        };

        for (std::size_t i = 0; i < d->action_descriptor_count; ++i) {
            const auto& ad = d->action_descriptors[i];
            const std::string action = ad.action ? ad.action : "(unnamed action)";
            const LegRow legs[] = {
                {"linux", ad.linux_leg},
                {"macos", ad.macos_leg},
                {"windows", ad.windows_leg},
            };
            for (const auto& leg_row : legs) {
                const auto& leg = leg_row.leg;
                out << "| " << escape_cell(name) << " | " << escape_cell(action) << " | "
                    << leg_row.os << " | " << support_name(leg.support) << " | "
                    << (leg.rung > 0 ? std::to_string(static_cast<int>(leg.rung)) : "-") << " | "
                    << (leg.mechanism && *leg.mechanism ? escape_cell(leg.mechanism) : "-") << " | "
                    << (leg.fallback && *leg.fallback ? escape_cell(leg.fallback) : "-") << " |\n";
            }
        }
    }

    out << "\n**Undeclared plugins** (ABI<4, or ABI4 with no capability declarations yet — "
           "RATCHET: this count must never grow):\n\n";
    if (undeclared.empty()) {
        out << "_none — every built plugin has adopted the ABI4 capability descriptor._\n";
    } else {
        for (const auto& n : undeclared) {
            out << "- `" << n << "`\n";
        }
    }
    out << "<!-- END GENERATED -->\n";

    std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
    if (!f) {
        std::cerr << "capmatrix-gen: cannot open output '" << out_path << "' for writing\n";
        return 1;
    }
    f << out.str();
    f.close();
    if (f.fail()) {
        std::cerr << "capmatrix-gen: write failed to '" << out_path << "'\n";
        return 1;
    }

    std::cerr << "capmatrix-gen: wrote " << plugins.size() << " plugin(s), " << undeclared.size()
              << " undeclared, to " << out_path << "\n";
    return 0;
}
