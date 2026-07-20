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
#include <yuzu/string_utils.hpp>

#include <nlohmann/json.hpp>

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
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

// A JSON value at `key` that isn't a string (or is absent) degrades to ""
// rather than throwing -- system_profiler's schema is not contractually
// typed, so a plugin/OS update that turns e.g. `_name` into a number (or
// omits it) must never crash the whole listing. Mirrors derive_publisher's
// find()+is_*() guard below.
inline std::string string_or_empty(const nlohmann::json& app_json, const char* key) {
    if (auto it = app_json.find(key); it != app_json.end() && it->is_string())
        return it->get<std::string>();
    return {};
}

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
// (string) `_name` is dropped, mirroring do_list_inventory's "row dropped if
// name is empty" contract -- an unnamed row can't be meaningfully reported.
// `version`/`path`/`lastModified` go through the same is_string() guard
// (detail::string_or_empty) but degrade to "" rather than dropping the
// record -- a non-string value there (e.g. a future system_profiler schema
// change) must never throw json::type_error, matching derive_publisher's
// existing guard below.
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
        rec.name = detail::string_or_empty(app_json, "_name");
        if (rec.name.empty())
            continue;
        rec.version = detail::string_or_empty(app_json, "version");
        rec.path = detail::string_or_empty(app_json, "path");
        rec.last_modified = detail::string_or_empty(app_json, "lastModified");
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
// yuzu::filesystem_macos type directly. Every dynamic (endpoint-controlled)
// field -- name/version/publisher/last_modified/bundle_id -- goes through
// safe_output_field so a hostile app name or bundle id can't inject a `|`
// column or a CR/LF row into the pipe-delimited stream; signature_status is
// our own enum-to-string and needs no escaping.
inline std::string
format_operator_list_row(const MacAppRecord& app,
                         const std::optional<yuzu::agent::SubprocessResult>& codesign_result,
                         const std::optional<yuzu::agent::SubprocessResult>& plutil_result) {
    const auto signature_status = signature_status_from(codesign_result);
    const auto bundle_id = bundle_id_from(plutil_result);
    return std::format(
        "app|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(app.name),
        app.version.empty() ? "-" : yuzu::util::safe_output_field(app.version),
        app.publisher.empty() ? "-" : yuzu::util::safe_output_field(app.publisher),
        app.last_modified.empty() ? "-" : yuzu::util::safe_output_field(app.last_modified),
        yuzu::filesystem_macos::to_string(signature_status),
        bundle_id.available ? yuzu::util::safe_output_field(bundle_id.value) : "-");
}

// BR-05: an sp_result with output_truncated set must render the honest
// truncated-listing sentinel row + nonzero rc, never fall through to the
// same-shaped "No applications found" rc-0 success row below it -- a >1MB
// system_profiler JSON truncates mid-object under run_bounded_subprocess's
// internal size cap and would otherwise parse to an empty vector,
// misreporting a real partial listing as a genuinely empty one.
// do_list_macos calls this first, before its apps.empty() check. Pulled out
// to a pure function (rather than inlined row/rc literals in the plugin) so
// a fixture test can inject a SubprocessResult and assert the row+rc
// pairing directly, without spawning system_profiler.
inline std::optional<std::pair<std::string, int>>
truncated_listing_outcome(const yuzu::agent::SubprocessResult& sp_result) {
    if (!sp_result.output_truncated)
        return std::nullopt;
    MacAppRecord none;
    none.name = "system_profiler output truncated -- listing incomplete";
    return std::make_pair(format_operator_list_row(none, std::nullopt, std::nullopt), 1);
}

} // namespace yuzu::installed_apps::macos_enrich
