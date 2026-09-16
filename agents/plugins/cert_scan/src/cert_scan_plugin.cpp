/**
 * cert_scan_plugin.cpp -- SSL/TLS certificate and private-key discovery
 * plugin for Yuzu.
 *
 * Walks every local user's home directory (auto-discovered per-OS, or an
 * operator-supplied `paths` override) looking for certificate material,
 * certificate signing requests, and -- the highest-value finding -- private
 * keys that escaped managed custody onto a developer or admin's own
 * filesystem. See docs/user-manual/agent-plugins.md's cert_scan entry for
 * the full threat model.
 *
 * Detection: a candidate-extension allowlist plus a `.ssh`-directory carve-
 * out (default-named OpenSSH keys like `id_rsa` carry no extension at all --
 * see cert_scan_collect.hpp's is_candidate_file() doc comment), then
 * content classification (cert_scan_rules.hpp's classify_content()/
 * classify_binary_content()) via PEM marker text, OpenSSH's own binary
 * key-header ciphername field, and (for .der/.cer/.p12/.pfx/JKS) binary
 * signatures.
 *
 * Never emits raw key material or certificate bytes -- only structural
 * metadata (subject/issuer/validity dates/serial/thumbprint for
 * certificates; a classification label and severity for keys and opaque
 * containers). A finding for a private key never includes so much as its
 * first byte.
 *
 * Severity ladder: CRITICAL (unencrypted private key) / HIGH (encrypted
 * private key, or a PKCS#12/JKS container -- opaque, not deep-parsed in
 * v1) / MEDIUM (expired or self-signed certificate) / LOW (valid
 * certificate) / INFO (certificate signing request).
 *
 * Action:
 *   "scan" -- One-shot walk. Params:
 *     paths    -- comma-separated list of directories to scan. Empty/absent
 *                 (the default) auto-discovers every local user's home
 *                 directory on this OS -- see cert_scan_collect.hpp's
 *                 discover_home_directories().
 *     maxDepth -- integer recursion depth cap (default 12).
 *
 * Output is pipe-delimited via write_output(), one row per finding:
 *   severity|kind|filePath|subject|issuer|notBefore|notAfter|serial|thumbprint
 * subject/issuer/notBefore/notAfter/serial/thumbprint are empty for every
 * kind other than "certificate" (keys, containers, and CSRs carry no
 * certificates_x509 fields).
 */

#include <yuzu/plugin.hpp>

#include <charconv>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <format>
#include <string>
#include <vector>

#include "cert_scan_collect.hpp"
#include "cert_scan_rules.hpp"

namespace {

using namespace yuzu::cert_scan;

// ABI v4+ per-action, per-OS capability declaration (#2204) -- read directly
// out of the built plugin binary by tools/capmatrix-gen to populate
// docs/os-capability-matrix.md's generated block. All three legs are the
// same acquisition shape: a portable std::filesystem walk (rung 1, no
// subprocess anywhere) plus in-process libcrypto PEM/DER parsing via
// certificates_x509.hpp -- only the home-directory DISCOVERY step differs
// per OS (cert_scan_collect.hpp's discover_home_directories()).
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "scan",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "std::filesystem walk of /home/* + /root; in-process libcrypto PEM/DER parse "
         "(certificates_x509.hpp)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "std::filesystem walk of /Users/* (excluding Shared/Guest); in-process libcrypto "
         "PEM/DER parse (certificates_x509.hpp)",
         nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "ProfileList registry read (win_profiles.hpp) for home-directory discovery, then "
         "std::filesystem walk; in-process libcrypto PEM/DER parse (certificates_x509.hpp)",
         "Per-user filesystem read access beyond the registry discovery hop is unmeasured on "
         "this build host -- a permission-denied degrades honestly (silent skip, "
         "enumerate_files' skip_permission_denied option), but the common-case outcome is not "
         "yet confirmed. See the plugin README's Caveats."},
    },
};

std::string escape_pipes(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '|')
            out += "\\|";
        else
            out += c;
    }
    return out;
}

std::vector<std::string> split_csv(std::string_view s) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= s.size()) {
        size_t comma = s.find(',', start);
        std::string_view piece =
            (comma == std::string_view::npos) ? s.substr(start) : s.substr(start, comma - start);
        size_t b = piece.find_first_not_of(" \t");
        size_t e = piece.find_last_not_of(" \t");
        if (b != std::string_view::npos)
            out.emplace_back(piece.substr(b, e - b + 1));
        if (comma == std::string_view::npos)
            break;
        start = comma + 1;
    }
    return out;
}

std::string today_iso() {
    const auto now = std::chrono::system_clock::now();
    const auto today = std::chrono::floor<std::chrono::days>(now);
    const std::chrono::year_month_day ymd{today};
    return std::format("{:04d}-{:02d}-{:02d}", static_cast<int>(ymd.year()),
                       static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()));
}

std::string lowercase_extension(const std::string& path) {
    std::string ext = std::filesystem::path(path).extension().string();
    for (char& c : ext)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return ext;
}

void output_finding(yuzu::CommandContext& ctx, const CertFinding& f, std::string_view file_path) {
    const auto& cf = f.cert_fields;
    ctx.write_output(std::format("{}|{}|{}|{}|{}|{}|{}|{}|{}", severity_name(f.severity),
                                 finding_kind_name(f.kind), escape_pipes(file_path), cf.subject,
                                 cf.issuer, cf.not_before, cf.not_after, cf.serial, cf.thumbprint));
}

void run_scan(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto paths = split_csv(params.get("paths", ""));

    ScanConfig cfg;
    cfg.roots = paths;
    if (auto max_depth_str = params.get("maxDepth", ""); !max_depth_str.empty()) {
        std::size_t depth = cfg.max_depth;
        auto [ptr, ec] = std::from_chars(max_depth_str.data(),
                                         max_depth_str.data() + max_depth_str.size(), depth);
        if (ec == std::errc{})
            cfg.max_depth = depth;
    }

    auto files = enumerate_files(cfg);
    const std::string today = today_iso();

    ctx.report_progress(0);
    std::size_t total_findings = 0;
    for (std::size_t i = 0; i < files.size(); ++i) {
        const auto& file = files[i];
        auto content = read_file_bytes(file.path, file.size_bytes);
        if (content) {
            std::vector<CertFinding> findings = has_any_pem_marker(*content)
                ? classify_content(*content, today)
                : classify_binary_content(*content, lowercase_extension(file.path), today);
            for (const auto& f : findings)
                output_finding(ctx, f, file.path);
            total_findings += findings.size();
        }
        if (!files.empty())
            ctx.report_progress(static_cast<int>((i + 1) * 100 / files.size()));
    }

    ctx.write_output(std::format("INFO|summary||{} files scanned, {} findings||||", files.size(),
                                 total_findings));
}

} // namespace

class CertScanPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "cert_scan"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "SSL/TLS certificate and private-key discovery -- walks every local user's home "
               "directory for certificate material, CSRs, and private keys that escaped managed "
               "custody. Never emits raw key material, only structural metadata.";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"scan", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext&) override { return {}; }

    void shutdown(yuzu::PluginContext&) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "scan") {
            run_scan(ctx, params);
            return 0;
        }
        ctx.write_output(
            std::format("ERROR|config|||||||unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(CertScanPlugin)
