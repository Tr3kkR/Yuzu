/**
 * licensing_linux.cpp — Linux detection surfaces for the license_scan plugin
 * (SLE roadmap §5 PR1 detection-surface table; ADR-0024 Decision 2).
 *
 * Surfaces (probe_status tokens):
 *   pkg_metadata      — rpm `%{LICENSE}` (probable) or dpkg DEP-5 copyright
 *                       headers (heuristic). Declared-licence CLASSIFICATION
 *                       only (license_type open_source|freeware|unknown) —
 *                       no lapse detection, a stated gap recorded in the
 *                       os-capability-matrix rows.
 *   entitlement_certs — RHEL entitlement certificates
 *                       (/etc/pki/entitlement/*.pem notAfter). Authoritative
 *                       subscription expiry. Uses `openssl x509` via
 *                       subprocess, matching the certificates plugin's
 *                       established agent crypto usage — the agent has no
 *                       shared in-process X509 helper.
 *   flexlm_lic        — FlexLM `.lic` files under conventional dirs, via the
 *                       ProbeSpec table rows (pure INCREMENT parser;
 *                       authoritative expiry).
 *
 * Primary-surface honesty (ADR-0024 D3): "success" is structural — the
 * enumeration completed (a query returning zero rows is success;
 * a failed subprocess is error).
 */

#ifdef __linux__

#include "licensing_parsers.hpp"
#include "licensing_probes.hpp"
#include "licensing_record.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::license_scan {

namespace {

// ── subprocess helpers (installed_apps precedent) ──────────────────────────

struct CommandResult {
    std::string output;
    bool ok = false; // popen succeeded AND the command exited 0
};

CommandResult run_command_rc(const char* cmd) {
    CommandResult result;
    std::array<char, 4096> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result.output += buf.data();
    }
    const int rc = pclose(pipe);
    result.ok = rc == 0;
    return result;
}

bool command_exists(const char* cmd) {
    const auto check = std::string("command -v ") + cmd + " >/dev/null 2>&1";
    return std::system(check.c_str()) == 0;
}

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        if (eol == std::string::npos)
            eol = text.size();
        if (eol > pos)
            lines.emplace_back(text.substr(pos, eol - pos));
        pos = eol + 1;
    }
    return lines;
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t pos = 0;
    while (pos <= line.size()) {
        std::size_t tab = line.find('\t', pos);
        if (tab == std::string::npos)
            tab = line.size();
        fields.emplace_back(line.substr(pos, tab - pos));
        if (tab == line.size())
            break;
        pos = tab + 1;
    }
    return fields;
}

// ── pkg_metadata (surface table Linux row 1) ───────────────────────────────

void run_pkg_metadata_surface(ProbeHost& host, std::vector<LicRecord>& records,
                              std::vector<ProbeOutcome>& outcomes) {
    std::size_t emitted = 0;

    if (command_exists("rpm")) {
        const auto res = run_command_rc(
            "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\t%{LICENSE}\\n' "
            "2>/dev/null");
        if (!res.ok) {
            outcomes.push_back({"pkg_metadata", false, 0, "rpm_query_failed"});
            return;
        }
        for (const auto& line : split_lines(res.output)) {
            const auto fields = split_tabs(line);
            if (fields.size() < 4 || fields[0].empty())
                continue;
            LicRecord r;
            r.product = fields[0];
            r.version = fields[1];
            r.vendor = fields[2] == "(none)" ? "" : fields[2];
            r.license_type = classify_license_string(fields[3]); // open_source|freeware|unknown
            r.status = "unknown"; // classification only — no lapse (stated gap)
            r.source = "package_metadata";
            r.confidence = "probable"; // declared by the packager
            records.push_back(std::move(r));
            ++emitted;
        }
        outcomes.push_back({"pkg_metadata", true, emitted, {}});
        return;
    }

    if (command_exists("dpkg-query")) {
        const auto res =
            run_command_rc("dpkg-query -W -f='${Package}\\t${Version}\\t${db:Status-Abbrev}\\n' "
                           "2>/dev/null");
        if (!res.ok) {
            outcomes.push_back({"pkg_metadata", false, 0, "dpkg_query_failed"});
            return;
        }
        for (const auto& line : split_lines(res.output)) {
            const auto fields = split_tabs(line);
            if (fields.size() < 3 || fields[0].empty())
                continue;
            // Installed or held (2nd status char 'i') — matches the
            // installed_apps/vuln_scan presence filter.
            if (fields[2].size() < 2 || fields[2][1] != 'i')
                continue;
            const std::string copyright_path = "/usr/share/doc/" + fields[0] + "/copyright";
            const auto content = host.read_file_prefix(copyright_path, 4096);
            if (!content || !is_dep5_copyright(*content))
                continue; // only machine-readable DEP-5 headers classify
            LicRecord r;
            r.product = fields[0];
            r.version = fields[1];
            r.license_type = classify_license_string(dep5_first_license(*content));
            r.status = "unknown";
            r.source = "package_metadata";
            r.confidence = "heuristic"; // header parse, not a packager field
            records.push_back(std::move(r));
            ++emitted;
        }
        outcomes.push_back({"pkg_metadata", true, emitted, {}});
        return;
    }

    // No supported package manager: structurally a successful probe of an
    // empty surface, not an error (nothing to enumerate).
    outcomes.push_back({"pkg_metadata", true, 0, {}});
}

// ── entitlement_certs (surface table Linux row 2; authoritative) ───────────

void run_entitlement_certs_surface(ProbeHost& host, std::vector<LicRecord>& records,
                                   std::vector<ProbeOutcome>& outcomes) {
    auto pems = host.glob("/etc/pki/entitlement/*.pem");
    // Entitlement key pairs live beside the certs as <serial>-key.pem — skip.
    std::vector<std::string> certs;
    for (auto& p : pems) {
        if (p.size() >= 8 && p.compare(p.size() - 8, 8, "-key.pem") == 0)
            continue;
        certs.push_back(std::move(p));
    }
    if (certs.empty()) {
        outcomes.push_back({"entitlement_certs", true, 0, {}});
        return;
    }
    if (!command_exists("openssl")) {
        // Certs exist but cannot be parsed — a real failure, not empty.
        outcomes.push_back({"entitlement_certs", false, 0, "openssl_unavailable"});
        return;
    }

    const long long now = host.now_epoch();
    std::size_t emitted = 0;
    bool any_parse_failure = false;
    for (const auto& cert : certs) {
        // -dateopt iso_8601 where supported; parse_openssl_enddate also
        // accepts the older default date format.
        auto res = run_command_rc(
            ("openssl x509 -noout -enddate -dateopt iso_8601 -in \"" + cert + "\" 2>/dev/null")
                .c_str());
        if (!res.ok)
            res = run_command_rc(
                ("openssl x509 -noout -enddate -in \"" + cert + "\" 2>/dev/null").c_str());
        const std::string not_after =
            res.ok ? parse_openssl_enddate(res.output) : std::string{};
        if (not_after.empty()) {
            any_parse_failure = true;
            continue;
        }
        LicRecord r;
        r.product = "Red Hat subscription entitlement";
        r.vendor = "Red Hat";
        r.license_type = "subscription";
        r.expires_at = not_after;
        // Compare against collection time on whole days (expires_at is a
        // date); the server-side evaluator re-derives lapse against its own
        // clock — this is the agent-observed state.
        const std::string today = iso_date_from_epoch(now);
        r.status = (!today.empty() && not_after < today) ? "expired" : "subscription_active";
        r.source = "entitlement_cert";
        r.confidence = "authoritative";
        records.push_back(std::move(r));
        ++emitted;
    }

    if (emitted == 0 && any_parse_failure)
        outcomes.push_back({"entitlement_certs", false, 0, "cert_parse_failed"});
    else
        outcomes.push_back({"entitlement_certs", true, emitted, {}});
}

} // namespace

// ── the Linux run ───────────────────────────────────────────────────────────

SurfaceRun run_platform_surfaces() {
    SurfaceRun run;
    ProbeHost host; // filesystem defaults; no registry on Linux

    run_pkg_metadata_surface(host, run.records, run.outcomes);
    run_entitlement_certs_surface(host, run.records, run.outcomes);

    // FlexLM conventional-dir rows ride the ProbeSpec table (flexlm_lic).
    run_probe_specs(host, Platform::linux_os, Scope::machine, run.records, run.outcomes);

    return run;
}

} // namespace yuzu::license_scan

#endif // __linux__
