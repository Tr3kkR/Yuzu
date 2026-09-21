/**
 * browser_policy_win.cpp — Windows leg entry point.
 *
 * PLACEHOLDER (P2b-1). The HKLM\SOFTWARE\Policies registry read lands in the
 * same PR's Windows package (P2b-2); until then the leg reports the honest
 * "not implemented" constraint rather than an empty success, so a host never
 * reads as "no policy configured" from a leg that did not look.
 */
#include "browser_policy_legs.hpp"

#if defined(_WIN32)

namespace yuzu::browser_policy {

int run_windows(yuzu::CommandContext& ctx) {
    mark_result_read(ctx, "windows:leg:not_implemented");
    return 0;
}

} // namespace yuzu::browser_policy

#endif // defined(_WIN32)
