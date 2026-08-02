#pragma once

#include <cstdint>
#include <string>

namespace yuzu::contracts::adr31 {

enum class ContractErrorCode : std::uint8_t {
    MalformedJson,
    RootNotObject,
    MissingField,
    NullField,
    WrongType,
    InvalidValue,
    UnsupportedVersion,
    ForbiddenAuthorityField,
    TooLarge,
    TooDeep,
    DuplicateKey,
};

struct ContractError {
    ContractErrorCode code;
    std::string path;
    std::string message;

    friend bool operator==(const ContractError&, const ContractError&) = default;
};

} // namespace yuzu::contracts::adr31
