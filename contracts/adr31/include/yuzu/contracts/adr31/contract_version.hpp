#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace yuzu::contracts::adr31 {

struct ContractVersion {
    std::uint16_t major;
    std::uint16_t minor;

    friend constexpr bool operator==(const ContractVersion&, const ContractVersion&) = default;
};

struct ContractDescriptor {
    std::string_view identifier;
    ContractVersion current;
    std::span<const ContractVersion> supported_versions;
};

inline constexpr ContractVersion kVersion1_0{1, 0};
inline constexpr std::array kInitialSupportedVersions{kVersion1_0};

inline constexpr ContractDescriptor kB2UseCaseRequest{
    "yuzu.b2.use_case.request", kVersion1_0,
    std::span<const ContractVersion>{kInitialSupportedVersions}};
inline constexpr ContractDescriptor kB2UseCaseResult{
    "yuzu.b2.use_case.result", kVersion1_0,
    std::span<const ContractVersion>{kInitialSupportedVersions}};
inline constexpr ContractDescriptor kB3PlatformRequest{
    "yuzu.b3.platform.request", kVersion1_0,
    std::span<const ContractVersion>{kInitialSupportedVersions}};
inline constexpr ContractDescriptor kB3PlatformResult{
    "yuzu.b3.platform.result", kVersion1_0,
    std::span<const ContractVersion>{kInitialSupportedVersions}};
inline constexpr ContractDescriptor kB4Fact{
    "yuzu.b4.fact", kVersion1_0,
    std::span<const ContractVersion>{kInitialSupportedVersions}};
inline constexpr ContractDescriptor kB4Finalisation{
    "yuzu.b4.finalisation", kVersion1_0,
    std::span<const ContractVersion>{kInitialSupportedVersions}};
inline constexpr ContractDescriptor kB4Redemption{
    "yuzu.b4.redemption", kVersion1_0,
    std::span<const ContractVersion>{kInitialSupportedVersions}};

inline constexpr std::array kContractDescriptors{
    kB2UseCaseRequest, kB2UseCaseResult, kB3PlatformRequest, kB3PlatformResult,
    kB4Fact,           kB4Finalisation, kB4Redemption,
};

[[nodiscard]] constexpr std::span<const ContractDescriptor> contract_descriptors() noexcept {
    return kContractDescriptors;
}

[[nodiscard]] constexpr bool supports(const ContractDescriptor& descriptor,
                                      ContractVersion candidate) noexcept {
    for (const auto supported : descriptor.supported_versions) {
        if (supported == candidate) return true;
    }
    return false;
}

} // namespace yuzu::contracts::adr31
