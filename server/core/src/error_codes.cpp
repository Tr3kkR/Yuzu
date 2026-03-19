#include "error_codes.hpp"

#include <algorithm>
#include <array>

namespace yuzu::server {

namespace {

constexpr std::array<ErrorCodeInfo, 15> kErrorTable{{
    // Plugin errors (1xxx)
    {kActionNotFound, "ActionNotFound", ErrorCategory::Plugin, false, 0},
    {kInvalidParameters, "InvalidParameters", ErrorCategory::Plugin, false, 0},
    {kPluginTimeout, "PluginTimeout", ErrorCategory::Plugin, true, 2},
    {kPluginCrash, "PluginCrash", ErrorCategory::Plugin, true, 2},
    {kExecutionFailed, "ExecutionFailed", ErrorCategory::Plugin, false, 0},

    // Transport errors (2xxx)
    {kStreamDisconnected, "StreamDisconnected", ErrorCategory::Transport, true, 3},
    {kDeliveryTimeout, "DeliveryTimeout", ErrorCategory::Transport, true, 3},
    {kNetworkError, "NetworkError", ErrorCategory::Transport, true, 3},

    // Orchestration errors (3xxx)
    {kDefinitionNotFound, "DefinitionNotFound", ErrorCategory::Orchestration, false, 0},
    {kApprovalRequired, "ApprovalRequired", ErrorCategory::Orchestration, false, 0},
    {kConcurrencyBlocked, "ConcurrencyBlocked", ErrorCategory::Orchestration, false, 0},
    {kScopeEmpty, "ScopeEmpty", ErrorCategory::Orchestration, false, 0},
    {kScheduleExpired, "ScheduleExpired", ErrorCategory::Orchestration, false, 0},

    // Agent errors (4xxx)
    {kAgentNotRegistered, "AgentNotRegistered", ErrorCategory::Agent, false, 0},
    {kPluginNotLoaded, "PluginNotLoaded", ErrorCategory::Agent, false, 0},
}};

const ErrorCodeInfo* find_entry(int code) {
    auto it = std::ranges::find(kErrorTable, code, &ErrorCodeInfo::code);
    return it != kErrorTable.end() ? &(*it) : nullptr;
}

} // namespace

ErrorCategory categorize(int code) {
    if (code >= 1000 && code < 2000)
        return ErrorCategory::Plugin;
    if (code >= 2000 && code < 3000)
        return ErrorCategory::Transport;
    if (code >= 3000 && code < 4000)
        return ErrorCategory::Orchestration;
    if (code >= 4000 && code < 5000)
        return ErrorCategory::Agent;
    return ErrorCategory::Unknown;
}

std::optional<ErrorCodeInfo> lookup(int code) {
    const auto* entry = find_entry(code);
    if (!entry)
        return std::nullopt;
    return *entry;
}

bool is_retryable(int code) {
    const auto* entry = find_entry(code);
    return entry ? entry->retryable : false;
}

int max_retry_attempts(int code) {
    const auto* entry = find_entry(code);
    return (entry && entry->retryable) ? entry->max_retries : 0;
}

std::string_view category_name(ErrorCategory cat) {
    switch (cat) {
    case ErrorCategory::Plugin:
        return "Plugin";
    case ErrorCategory::Transport:
        return "Transport";
    case ErrorCategory::Orchestration:
        return "Orchestration";
    case ErrorCategory::Agent:
        return "Agent";
    case ErrorCategory::Unknown:
        return "Unknown";
    }
    return "Unknown";
}

} // namespace yuzu::server
