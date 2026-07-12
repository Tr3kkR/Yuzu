// libFuzzer harness for server/core/src/yaml_scan.{hpp,cpp} — the in-tree
// minimal YAML scanner that is the ONLY runtime consumer of operator-supplied
// `yaml_source` blobs (there is deliberately no YAML library server-side; see
// the header). Since #1215 these scanners are load-bearing for authorization
// (scope_yaml lowers the `scope:` block that gates command targeting), so
// memory-safety over arbitrary bytes matters.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh — keep
// the two in sync when adding sources.

#include "yaml_scan.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace ys = yuzu::server::yaml_scan;
    const std::string yaml(reinterpret_cast<const char*>(data), size);

    // The keys the production callers actually look up…
    for (const char* key : {"apiVersion", "kind", "name", "scope", "spec", "expression"}) {
        (void)ys::extract_yaml_value(yaml, key);
        (void)ys::extract_yaml_list(yaml, key);
        (void)ys::extract_yaml_mapping(yaml, key);
        (void)ys::yaml_has_key(yaml, key);
    }
    for (const char* path : {"spec.scope", "metadata.name", "spec.spec.spec"}) {
        (void)ys::extract_yaml_section(yaml, path);
    }

    // …and an attacker-shaped key taken from the input itself (first line),
    // which explores the substring-match / superstring-key edge the header's
    // SECURITY CONTRACT calls out.
    const auto nl = yaml.find('\n');
    const std::string fuzz_key = yaml.substr(0, nl == std::string::npos ? size : nl);
    if (!fuzz_key.empty() && fuzz_key.size() <= 128) {
        (void)ys::extract_yaml_value(yaml, fuzz_key);
        (void)ys::extract_yaml_section(yaml, fuzz_key);
        (void)ys::yaml_has_key(yaml, fuzz_key);
    }
    return 0;
}
