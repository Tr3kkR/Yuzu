/**
 * local_security_policy_linux.cpp -- Linux leg: bounded reads of login.defs,
 * pwquality/faillock config, /etc/pam.d, audit.rules and sudoers through the
 * shared pure collector (local_security_policy_parsers.hpp).
 */
#include "local_security_policy_legs.hpp"

#if defined(__linux__)

namespace yuzu::local_security_policy {

int collect_linux_policy(yuzu::CommandContext& ctx, std::string_view action) {
    return apply_collected(ctx, collect_file_policy(FileFlavor::Linux, parse_local_policy_action(action),
                                                    posix_read_file, posix_list_dir));
}

} // namespace yuzu::local_security_policy

#endif // defined(__linux__)
