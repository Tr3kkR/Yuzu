// tar_cursor_sources.cpp -- assembles the cursor-model sources this agent
// ships. See tar_cursor.hpp for the CursorSource contract.

#include "tar_cursor.hpp"

namespace yuzu::tar {

// Empty on purpose in this change: the seam ships the contract, the durable
// cursor table and the driver, and each consuming source registers itself here
// when it lands. tar_plugin.cpp already builds cursor_sources_ from this
// function's return value at init(), so a source needs no plugin-side change
// to light up.
std::vector<std::unique_ptr<CursorSource>> make_cursor_sources() {
    std::vector<std::unique_ptr<CursorSource>> sources;
    return sources;
}

} // namespace yuzu::tar
