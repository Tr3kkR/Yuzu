#if defined(_WIN32)
#include "disk_actions_legs.hpp"
namespace yuzu::disk_actions {
int emit_smart(yuzu::CommandContext& ctx) { (void)ctx; return 0; }
int emit_volumes(yuzu::CommandContext& ctx) { (void)ctx; return 0; }
} // namespace yuzu::disk_actions
#endif
