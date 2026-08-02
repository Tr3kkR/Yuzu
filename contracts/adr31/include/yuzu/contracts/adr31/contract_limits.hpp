#pragma once

#include <cstddef>

namespace yuzu::contracts::adr31 {

inline constexpr std::size_t kMaxContractWireBytes = 64 * 1024;
inline constexpr std::size_t kMaxContractNestingDepth = 32;

} // namespace yuzu::contracts::adr31
