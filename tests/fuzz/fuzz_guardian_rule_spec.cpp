// libFuzzer harness for server/core/src/guardian_rule_spec.cpp — derivation of
// a Guardian rule's canonical spec from an operator REST body, plus the
// dangerous-enforce chokepoints (`dangerous_enforce_in_spec` and friends) that
// gate enforce-mode promotion on every path (CLAUDE.md "Guardian engine"
// invariant). All inputs here arrive from the network.
//
// nlohmann json::exception from derive_rule_spec is swallowed: the REST layer
// parses/dispatches under its own guard, so the fuzz signal we want is memory
// safety + UB, not json type-mismatch throws. If a future audit confirms an
// uncaught-throw path from a handler, tighten this to let it crash.
//
// Registered in tests/fuzz/meson.build AND .clusterfuzzlite/build.sh — keep
// the two in sync when adding sources.

#include "guardian_rule_spec.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace gd = yuzu::server::guardian;
    const std::string_view in(reinterpret_cast<const char*>(data), size);
    const std::string as_str(in);

    // The three chokepoints take raw strings — feed them the input directly.
    (void)gd::dangerous_enforce_registry_key(in);
    (void)gd::dangerous_enforce_service_stop(in);
    (void)gd::dangerous_enforce_in_spec(as_str);

    // Structured derivation from a parsed body (parse errors → discarded, no
    // throw). Alternate audit/enforce so the enforce-only validation runs.
    const auto body = nlohmann::json::parse(in, /*cb=*/nullptr, /*allow_exceptions=*/false);
    if (!body.is_discarded() && body.is_object()) {
        const char* mode = (size % 2 == 0) ? "audit" : "enforce";
        try {
            (void)gd::derive_rule_spec(body, "fuzz-rule", 1, true, mode);
        } catch (const nlohmann::json::exception&) {
            // See header comment — type-mismatch throws are out of scope v1.
        }
    }
    return 0;
}
