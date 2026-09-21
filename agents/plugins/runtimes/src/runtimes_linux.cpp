/**
 * runtimes_linux.cpp -- Linux leg entry point.
 *
 * COMPILING STUB. The real injected-root walks (dotnet install trees, JVM
 * `release` files, Python interpreter names/dirs) replace this body in the
 * Linux-leg package. Until then every action reports
 * `status|<action>|unsupported|linux:leg:not_implemented` -- an honest
 * "not read", never an empty `supported` success.
 */
#include "runtimes_legs.hpp"

#if defined(__linux__)

namespace yuzu::runtimes {

int run_linux(yuzu::CommandContext& ctx, Action a) {
    emit_planned(ctx, a, "linux:leg:not_implemented");
    return 0;
}

} // namespace yuzu::runtimes

#endif // defined(__linux__)
