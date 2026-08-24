#pragma once

/**
 * tar_service_parsers.hpp -- pure output parsers for the TAR service
 * collector's Linux (`systemctl list-units`) and macOS (`launchctl list`)
 * enumeration legs (runner-convergence PR, ADR-3002 rung 2 migration).
 *
 * Header-only, no I/O: tar_service_collector.cpp owns running
 * systemctl/launchctl through the bounded, shell-free runner
 * (yuzu::agent::run_bounded_subprocess) and hands this header the captured
 * SubprocessResult::lines, so every parser here is unit-testable directly
 * against fixture line arrays with no live systemctl/launchctl dependency
 * (see tests/unit/test_tar_service.cpp). Mirrors the
 * services_parsers.hpp / firewall_parsers.hpp / route_sysctl_arp.hpp split
 * already established elsewhere in this repo.
 *
 * This is a straight extraction of the two inline parsing loops the
 * collector used to run over the old pipe-read output -- column handling,
 * header skipping, and PID|LABEL|NAME semantics are unchanged, so collector
 * output for identical input text stays byte-identical to before the
 * runner migration.
 */

#include "tar_collectors.hpp" // yuzu::tar::ServiceInfo

#include <cstddef>
#include <string>
#include <vector>

namespace yuzu::tar {

/// Parse the line-split stdout of `systemctl list-units --type=service
/// --all --no-pager --no-legend` (SubprocessResult::lines -- blank lines
/// already dropped and a trailing '\r' already stripped by the runner).
/// Tolerant of a leading whitespace/bullet column (systemctl marks a failed
/// unit with "*"); `--no-legend` means there is no header row to skip.
inline std::vector<ServiceInfo>
parse_systemctl_list_units(const std::vector<std::string>& lines) {
    std::vector<ServiceInfo> services;
    services.reserve(lines.size());

    for (std::string line : lines) {
        // Trim leading whitespace and the bullet systemctl marks a failed
        // unit with.
        auto start = line.find_first_not_of(" *");
        if (start == std::string::npos)
            continue;
        line = line.substr(start);

        ServiceInfo si;
        std::size_t pos = 0;
        auto next_token = [&]() -> std::string {
            auto s = line.find_first_not_of(' ', pos);
            if (s == std::string::npos)
                return {};
            auto e = line.find(' ', s);
            if (e == std::string::npos)
                e = line.size();
            pos = e;
            return line.substr(s, e - s);
        };

        si.name = next_token();     // UNIT
        next_token();               // LOAD
        next_token();               // ACTIVE
        si.status = next_token();   // SUB
        // Remainder is description
        auto desc_start = line.find_first_not_of(' ', pos);
        if (desc_start != std::string::npos)
            si.display_name = line.substr(desc_start);

        si.startup_type = "unknown";
        services.push_back(std::move(si));
    }

    return services;
}

/// Parse the line-split stdout of `launchctl list`
/// (SubprocessResult::lines -- blank lines already dropped and a trailing
/// '\r' already stripped by the runner). The first line is always the
/// "PID\tStatus\tLabel" header and is skipped unconditionally, matching the
/// original fgets-based skip; an empty `lines` (no output at all) yields an
/// empty result, same as the original no-output early return.
inline std::vector<ServiceInfo> parse_launchctl_list(const std::vector<std::string>& lines) {
    std::vector<ServiceInfo> services;
    if (lines.empty())
        return services;
    services.reserve(lines.size() - 1);

    for (std::size_t i = 1; i < lines.size(); ++i) {
        const std::string& line = lines[i];

        // Format: PID\tStatus\tLabel
        ServiceInfo si;
        std::size_t pos = 0;
        auto next_field = [&]() -> std::string {
            auto tab = line.find('\t', pos);
            std::string field;
            if (tab == std::string::npos) {
                field = line.substr(pos);
                pos = line.size();
            } else {
                field = line.substr(pos, tab - pos);
                pos = tab + 1;
            }
            return field;
        };

        auto pid_str = next_field();
        next_field(); // status code
        si.name = next_field();

        si.status = (pid_str != "-" && !pid_str.empty()) ? "running" : "stopped";
        // macOS launchctl list does not provide startup type; 'unknown' is correct
        si.startup_type = "unknown";
        services.push_back(std::move(si));
    }

    return services;
}

} // namespace yuzu::tar
