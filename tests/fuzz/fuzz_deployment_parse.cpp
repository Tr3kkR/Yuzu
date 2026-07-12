// libFuzzer harness for server/core/src/deployment_parse.hpp — validators for
// operator-supplied deployment config (URL / filename / SHA-256 / args) and
// the content_dist stage/exec pipe-output parsers. Both directions carry
// untrusted input: config fields from the REST body, output bytes from the
// agent's plugin.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh — keep
// the two in sync when adding sources.

#include "deployment_parse.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace dp = yuzu::server::deployment;
    const std::string_view in(reinterpret_cast<const char*>(data), size);

    // Field validators over the raw bytes.
    (void)dp::is_valid_filename(in);
    (void)dp::is_valid_sha256(in);
    (void)dp::is_valid_url(in);
    (void)dp::is_valid_args(in);

    // config_valid over a config whose fields are slices of the input.
    const auto q = size / 4;
    dp::DeploymentConfig cfg;
    cfg.url = std::string(in.substr(0, q));
    cfg.filename = std::string(in.substr(q, q));
    cfg.sha256 = std::string(in.substr(2 * q, q));
    cfg.args = std::string(in.substr(3 * q));
    std::string why;
    (void)dp::config_valid(cfg, &why);

    // Phase parsers with every proto-status class (0 running / 1 success /
    // 2 failure) against the same output bytes.
    for (int status : {0, 1, 2}) {
        (void)dp::parse_stage(status, in);
        (void)dp::parse_exec(status, in);
    }
    return 0;
}
