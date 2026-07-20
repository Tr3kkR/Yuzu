#pragma once

// installed_apps_macos_enrich.hpp -- pure macOS operator-listing enrichment
// for the installed_apps plugin's `list` action (#2273/1.10).
//
// Two independent pure pieces live here, mirroring filesystem_macos_sig.hpp's
// "impure collection / pure mapping" split so both run on every CI host
// without a macOS box or the real system_profiler/codesign/plutil binaries:
//
//   1. parse_system_profiler_apps_json() -- `system_profiler -json
//      SPApplicationsDataType` output -> a per-app record carrying the REAL
//      bundle path (never a synthesised /Applications/<name>.app -- PLAN-05).
//      An app whose JSON record has no usable path is still returned, with
//      `path` empty -- the caller must not attempt codesign/plutil against
//      it.
//
//   2. format_operator_list_row() -- one app record plus its (optional)
//      codesign/plutil SubprocessResults -> the pipe-delimited `app|...` row
//      installed_apps_plugin.cpp's do_list() macOS path emits, applying the
//      PLAN-02 short-circuit: a nullopt result (never attempted -- no usable
//      path, or the listing's cap/budget was already spent) and a timed_out
//      result (attempted but killed at its deadline) degrade identically to
//      an honest unknown signature_status / absent bundle_id -- neither is
//      ever classified from a partial or fabricated verdict.
//
// The plugin owns ALL subprocess plumbing (run_bounded_subprocess calls,
// budget/cap bookkeeping) -- this header only parses text and shapes rows.

#include "filesystem_macos_sig.hpp"

#include <yuzu/agent/subprocess_runner.hpp>

#include <nlohmann/json.hpp>

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::installed_apps::macos_enrich {

// One `system_profiler -json SPApplicationsDataType` array element, reduced
// to what the operator `list` row needs. `path` is the app's real bundle
// path (the JSON's `path` key) -- the only thing codesign and
// `plutil -extract ... Contents/Info.plist` can run against; empty when the
// JSON record carries none (never synthesised -- PLAN-05).
struct MacAppRecord {
    std::string name;
    std::string version;
    std::string path;
    std::string publisher;
    std::string last_modified;
};

namespace detail {

// `signed_by` (when present) is the codesign certificate chain, leaf first
// -- e.g. ["Developer ID Application: Spotify (2FNC3A47ZF)", "Developer ID
// Certification Authority", "Apple Root CA"] for a third-party app, or
// ["Software Signing", "Apple Code Signing Certification Authority", "Apple
// Root CA"] for an Apple one. The leaf entry is the closest thing macOS
// exposes to a Windows-style Publisher string, so it wins when present.
// `obtained_from` (apple/mac_app_store/identified_developer/unknown) is the
// fallback for the unsigned-observable case; "unknown" carries no more
// information than an absent field, so it maps to "-" rather than being
// echoed verbatim -- never guessed, matching this plugin's existing "-"
// placeholder convention for an honestly-unknown field.
inline std::string derive_publisher(const nlohmann::json& app_json) {
    if (auto it = app_json.find("signed_by"); it != app_json.end() && it->is_array() &&
        !it->empty()) {
        const auto& leaf = it->front();
        if (leaf.is_string()) {
            auto s = leaf.get<std::string>();
            if (!s.empty())
                return s;
        }
    }
    if (auto it = app_json.find("obtained_from"); it != app_json.end() && it->is_string()) {
        auto s = it->get<std::string>();
        if (!s.empty() && s != "unknown")
            return s;
    }
    return "-";
}

} // namespace detail

// Parses the top-level `{"SPApplicationsDataType": [...]}` document. Malformed
// JSON, a missing/non-array `SPApplicationsDataType`, or a non-object array
// element all degrade to that element (or the whole result) being skipped --
// never a thrown exception, matching this codebase's
// json::parse(..., allow_exceptions=false) convention for subprocess-derived
// JSON (dex_linux_journal.cpp, tar_software_core.cpp). A record with no
// `_name` is dropped, mirroring do_list_inventory's "row dropped if name is
// empty" contract -- an unnamed row can't be meaningfully reported.
inline std::vector<MacAppRecord> parse_system_profiler_apps_json(std::string_view json_text) {
    std::vector<MacAppRecord> out;

    auto doc = nlohmann::json::parse(json_text, nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded() || !doc.is_object())
        return out;

    auto apps_it = doc.find("SPApplicationsDataType");
    if (apps_it == doc.end() || !apps_it->is_array())
        return out;

    out.reserve(apps_it->size());
    for (const auto& app_json : *apps_it) {
        if (!app_json.is_object())
            continue;

        MacAppRecord rec;
        rec.name = app_json.value("_name", "");
        if (rec.name.empty())
            continue;
        rec.version = app_json.value("version", "");
        rec.path = app_json.value("path", "");
        rec.last_modified = app_json.value("lastModified", "");
        rec.publisher = detail::derive_publisher(app_json);
        out.push_back(std::move(rec));
    }
    return out;
}

// PLAN-02 short-circuit: `result` is nullopt when the app was never enriched
// at all (no usable `path`, or the listing's cap/budget was already spent
// before this app's turn) -- a different code path from a subprocess call
// that ran and returned something, but deliberately folded into the SAME
// honest "unknown" outcome as a call that hit its deadline
// (`result->timed_out`), since neither case has a trustworthy verdict to
// report.
inline yuzu::filesystem_macos::SignatureStatus
signature_status_from(const std::optional<yuzu::agent::SubprocessResult>& result) {
    if (!result || result->timed_out)
        return yuzu::filesystem_macos::SignatureStatus::unknown;
    return yuzu::filesystem_macos::classify_codesign_result(result->tool_ran, result->exit_code,
                                                             result->output);
}

// Same short-circuit as signature_status_from, for the plutil bundle_id
// extraction.
inline yuzu::filesystem_macos::PlutilExtractResult
bundle_id_from(const std::optional<yuzu::agent::SubprocessResult>& result) {
    if (!result || result->timed_out)
        return {};
    return yuzu::filesystem_macos::classify_plutil_extract(result->tool_ran, result->exit_code,
                                                            result->output);
}

// One `app|` row for the operator `list` action's macOS path: the original
// name/version/publisher/install_date columns, then the PLAN-03 append of
// signature_status/bundle_id. `codesign_result`/`plutil_result` are the raw
// run_bounded_subprocess() results (nullopt if that subprocess was never
// attempted for this app) -- classification and the timed_out short-circuit
// happen inside this function so the plugin's do_list() never has to name a
// yuzu::filesystem_macos type directly.
inline std::string
format_operator_list_row(const MacAppRecord& app,
                         const std::optional<yuzu::agent::SubprocessResult>& codesign_result,
                         const std::optional<yuzu::agent::SubprocessResult>& plutil_result) {
    const auto signature_status = signature_status_from(codesign_result);
    const auto bundle_id = bundle_id_from(plutil_result);
    return std::format("app|{}|{}|{}|{}|{}|{}", app.name,
                        app.version.empty() ? "-" : app.version,
                        app.publisher.empty() ? "-" : app.publisher,
                        app.last_modified.empty() ? "-" : app.last_modified,
                        yuzu::filesystem_macos::to_string(signature_status),
                        bundle_id.available ? bundle_id.value : "-");
}

} // namespace yuzu::installed_apps::macos_enrich
