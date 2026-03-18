#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

namespace yuzu::server {

enum class ErrorCategory { Plugin, Transport, Orchestration, Agent, Unknown };

struct ErrorCodeInfo {
    int code;
    const char* name;
    ErrorCategory category;
    bool retryable;
    int max_retries;
};

// ---- Plugin errors (1xxx) ----
inline constexpr int kActionNotFound = 1001;
inline constexpr int kInvalidParameters = 1002;
inline constexpr int kPluginTimeout = 1003;
inline constexpr int kPluginCrash = 1004;
inline constexpr int kExecutionFailed = 1005;

// ---- Transport errors (2xxx) ----
inline constexpr int kStreamDisconnected = 2001;
inline constexpr int kDeliveryTimeout = 2002;
inline constexpr int kNetworkError = 2003;

// ---- Orchestration errors (3xxx) ----
inline constexpr int kDefinitionNotFound = 3001;
inline constexpr int kApprovalRequired = 3002;
inline constexpr int kConcurrencyBlocked = 3003;
inline constexpr int kScopeEmpty = 3004;
inline constexpr int kScheduleExpired = 3005;

// ---- Agent errors (4xxx) ----
inline constexpr int kAgentNotRegistered = 4001;
inline constexpr int kPluginNotLoaded = 4002;

/// Derive the category from a numeric error code based on its range.
ErrorCategory categorize(int code);

/// Look up the full ErrorCodeInfo for a given code. Returns std::nullopt for unknown codes.
std::optional<ErrorCodeInfo> lookup(int code);

/// Returns true if the error code is eligible for automatic retry.
bool is_retryable(int code);

/// Returns the maximum retry attempts for a retryable code, or 0 if not retryable.
int max_retry_attempts(int code);

/// Returns a human-readable name for the category.
std::string_view category_name(ErrorCategory cat);

} // namespace yuzu::server
