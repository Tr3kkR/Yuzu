/**
 * ssh_hardening_plugin.cpp — SSH server (sshd_config) hardening audit plugin.
 *
 * Audits /etc/ssh/sshd_config (and any files it Includes) against the
 * Mozilla "Modern" OpenSSH baseline: https://wiki.mozilla.org/Security/Guidelines/OpenSSH
 * Checks KexAlgorithms, Ciphers, MACs, and HostKey against an approved
 * allow-list. Audit-only — never modifies sshd_config.
 *
 * Linux-only: sshd_config lives at a fixed POSIX path and Include glob
 * expansion here uses glob(3); see docs/os-capability-matrix.md.
 *
 * Action:
 *   "audit" — Run the compliance check and report findings.
 *
 * Output is pipe-delimited via write_output(), matching the vuln_scan
 * plugin's convention:
 *   <severity>|<category>|<title>|<detail>
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <string>
#include <vector>

#include "ssh_hardening_collect.hpp"
#include "ssh_hardening_rules.hpp"

namespace {

using yuzu::ssh_hardening::ConfigCheckResult;

// Escape pipe characters in output values (same convention as vuln_scan).
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

constexpr std::string_view kCategory = "ssh_hardening";

void output_results(yuzu::CommandContext& ctx, const std::vector<ConfigCheckResult>& results) {
    for (const auto& r : results) {
        ctx.write_output(std::format("{}|{}|{}|{}", r.severity, kCategory, r.title,
                                     escape_pipes(r.detail)));
    }
}

#ifdef __linux__
std::vector<ConfigCheckResult> run_audit() {
    auto effective = yuzu::ssh_hardening::collect_effective_sshd_config();
    if (!effective) {
        return {{"INFO", "sshd_config",
                 "/etc/ssh/sshd_config not found -- OpenSSH server does not appear to be "
                 "installed on this host",
                 true}};
    }
    return yuzu::ssh_hardening::evaluate_ssh_hardening(*effective);
}
#else
std::vector<ConfigCheckResult> run_audit() {
    return {{"INFO", "sshd_config", "ssh_hardening audit is only supported on Linux", true}};
}
#endif

} // namespace

class SshHardeningPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "ssh_hardening"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "SSH server hardening audit -- checks sshd_config KexAlgorithms/Ciphers/MACs/"
               "HostKey against the Mozilla Modern OpenSSH baseline";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"audit", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                [[maybe_unused]] yuzu::Params params) override {
        if (action == "audit") {
            ctx.report_progress(0);
            auto results = run_audit();
            output_results(ctx, results);
            ctx.report_progress(100);
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(SshHardeningPlugin)
