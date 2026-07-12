// libFuzzer harness for server/core/src/preflight_parse.hpp — the pure,
// header-only parser for pipe-delimited plugin output that feeds the /auto
// pre-flight verdict grid. Input here is agent-controlled bytes (a hostile or
// buggy plugin can emit anything), so the whole surface must be total.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh — keep
// the two in sync when adding sources.

#include "preflight_parse.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace pf = yuzu::server::preflight;
    const std::string_view in(reinterpret_cast<const char*>(data), size);

    // Low-level helpers straight over the raw bytes.
    (void)pf::split_pipe(in);
    (void)pf::find_row(in, "app");
    (void)pf::parse_i64(in);

    // cmp_version with two halves of the input (both operator-controlled in
    // production via the /auto form's threshold strings).
    const auto half = size / 2;
    (void)pf::cmp_version(std::string(in.substr(0, half)), std::string(in.substr(half)));

    // evaluate() across every catalogue key, with the two interesting config
    // shapes (thresholds set / unset — flips the Pass/Fail/Warn branches).
    pf::PreflightConfig loose;
    pf::PreflightConfig strict;
    strict.app_name = "app";
    strict.app_min_version = "1.2.3";
    strict.app_max_version = "9.9.9";
    strict.os_min_version = "10.0";
    strict.req_arch = "x86_64";
    strict.min_free_gib = 20;
    strict.reboot_block = true;
    loose.reboot_block = false;

    for (const char* key : {"app", "osver", "osarch", "disk", "reboot", "bogus"}) {
        (void)pf::evaluate(key, in, loose);
        (void)pf::evaluate(key, in, strict);
        (void)pf::extract_cell(key, in);
    }

    // Grid roll-up: one device, two checks, the fuzz input as the raw output —
    // exercises the error|-prefix, empty-output and status backstop paths.
    std::vector<pf::PreflightTarget> targets(1);
    targets[0].agent_id = "agent-1";
    std::vector<pf::PreflightCheckResponses> checks(2);
    checks[0].key = "disk";
    checks[0].by_agent["agent-1"] = {size % 3 == 0 ? 0 : (size % 3 == 1 ? 1 : 2), std::string(in)};
    checks[1].key = "reboot"; // no response for this check → pending path
    bool pending = false;
    (void)pf::compute_device_results(targets, checks, strict, &pending);
    return 0;
}
