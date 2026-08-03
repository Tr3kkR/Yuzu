#pragma once

#include <cstddef>

namespace yuzu::contracts::adr31 {

inline constexpr std::size_t kMaxContractWireBytes = 64 * 1024;
inline constexpr std::size_t kMaxContractNestingDepth = 32;
inline constexpr std::size_t kMinOpaqueRunIdCharacters = 22;
inline constexpr std::size_t kMaxOpaqueRunIdCharacters = 128;
inline constexpr std::size_t kMaxCorrelationIdCharacters = 128;

} // namespace yuzu::contracts::adr31
