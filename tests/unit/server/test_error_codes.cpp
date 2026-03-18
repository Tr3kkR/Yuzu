/**
 * test_error_codes.cpp — Unit tests for error code taxonomy
 *
 * Covers: categorize, lookup, is_retryable, max_retry_attempts, category_name.
 */

#include "error_codes.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::server;

// ── categorize ──────────────────────────────────────────────────────────────

TEST_CASE("ErrorCodes: categorize Plugin range", "[error_codes]") {
    CHECK(categorize(1001) == ErrorCategory::Plugin);
    CHECK(categorize(1005) == ErrorCategory::Plugin);
    CHECK(categorize(1999) == ErrorCategory::Plugin);
}

TEST_CASE("ErrorCodes: categorize Transport range", "[error_codes]") {
    CHECK(categorize(2001) == ErrorCategory::Transport);
    CHECK(categorize(2003) == ErrorCategory::Transport);
    CHECK(categorize(2999) == ErrorCategory::Transport);
}

TEST_CASE("ErrorCodes: categorize Orchestration range", "[error_codes]") {
    CHECK(categorize(3001) == ErrorCategory::Orchestration);
    CHECK(categorize(3005) == ErrorCategory::Orchestration);
    CHECK(categorize(3999) == ErrorCategory::Orchestration);
}

TEST_CASE("ErrorCodes: categorize Agent range", "[error_codes]") {
    CHECK(categorize(4001) == ErrorCategory::Agent);
    CHECK(categorize(4002) == ErrorCategory::Agent);
    CHECK(categorize(4999) == ErrorCategory::Agent);
}

TEST_CASE("ErrorCodes: categorize Unknown for out-of-range", "[error_codes]") {
    CHECK(categorize(0) == ErrorCategory::Unknown);
    CHECK(categorize(999) == ErrorCategory::Unknown);
    CHECK(categorize(5000) == ErrorCategory::Unknown);
    CHECK(categorize(-1) == ErrorCategory::Unknown);
    CHECK(categorize(99999) == ErrorCategory::Unknown);
}

// ── lookup ──────────────────────────────────────────────────────────────────

TEST_CASE("ErrorCodes: lookup known codes", "[error_codes]") {
    SECTION("Plugin codes") {
        auto info = lookup(kActionNotFound);
        REQUIRE(info.has_value());
        CHECK(info->code == 1001);
        CHECK(info->category == ErrorCategory::Plugin);
        CHECK(std::string(info->name) == "ActionNotFound");

        auto timeout = lookup(kPluginTimeout);
        REQUIRE(timeout.has_value());
        CHECK(timeout->code == 1003);
        CHECK(timeout->retryable == true);
    }

    SECTION("Transport codes") {
        auto info = lookup(kStreamDisconnected);
        REQUIRE(info.has_value());
        CHECK(info->code == 2001);
        CHECK(info->category == ErrorCategory::Transport);
        CHECK(info->retryable == true);
    }

    SECTION("Orchestration codes") {
        auto info = lookup(kDefinitionNotFound);
        REQUIRE(info.has_value());
        CHECK(info->code == 3001);
        CHECK(info->category == ErrorCategory::Orchestration);
        CHECK(info->retryable == false);
    }

    SECTION("Agent codes") {
        auto info = lookup(kAgentNotRegistered);
        REQUIRE(info.has_value());
        CHECK(info->code == 4001);
        CHECK(info->category == ErrorCategory::Agent);
    }
}

TEST_CASE("ErrorCodes: lookup unknown code returns nullopt", "[error_codes]") {
    CHECK_FALSE(lookup(9999).has_value());
    CHECK_FALSE(lookup(0).has_value());
    CHECK_FALSE(lookup(1999).has_value());
}

// ── is_retryable ────────────────────────────────────────────────────────────

TEST_CASE("ErrorCodes: is_retryable for transport errors", "[error_codes]") {
    CHECK(is_retryable(kStreamDisconnected) == true);
    CHECK(is_retryable(kDeliveryTimeout) == true);
    CHECK(is_retryable(kNetworkError) == true);
}

TEST_CASE("ErrorCodes: is_retryable for plugin 1003/1004", "[error_codes]") {
    CHECK(is_retryable(kPluginTimeout) == true);
    CHECK(is_retryable(kPluginCrash) == true);
}

TEST_CASE("ErrorCodes: is_retryable false for non-retryable codes", "[error_codes]") {
    CHECK(is_retryable(kActionNotFound) == false);
    CHECK(is_retryable(kInvalidParameters) == false);
    CHECK(is_retryable(kExecutionFailed) == false);
    CHECK(is_retryable(kDefinitionNotFound) == false);
    CHECK(is_retryable(kApprovalRequired) == false);
    CHECK(is_retryable(kAgentNotRegistered) == false);
    CHECK(is_retryable(kPluginNotLoaded) == false);
}

TEST_CASE("ErrorCodes: is_retryable false for unknown codes", "[error_codes]") {
    CHECK(is_retryable(9999) == false);
    CHECK(is_retryable(0) == false);
}

// ── max_retry_attempts ──────────────────────────────────────────────────────

TEST_CASE("ErrorCodes: max_retry_attempts 3 for transport", "[error_codes]") {
    CHECK(max_retry_attempts(kStreamDisconnected) == 3);
    CHECK(max_retry_attempts(kDeliveryTimeout) == 3);
    CHECK(max_retry_attempts(kNetworkError) == 3);
}

TEST_CASE("ErrorCodes: max_retry_attempts 2 for retryable plugin", "[error_codes]") {
    CHECK(max_retry_attempts(kPluginTimeout) == 2);
    CHECK(max_retry_attempts(kPluginCrash) == 2);
}

TEST_CASE("ErrorCodes: max_retry_attempts 0 for non-retryable", "[error_codes]") {
    CHECK(max_retry_attempts(kActionNotFound) == 0);
    CHECK(max_retry_attempts(kDefinitionNotFound) == 0);
    CHECK(max_retry_attempts(kAgentNotRegistered) == 0);
}

TEST_CASE("ErrorCodes: max_retry_attempts 0 for unknown", "[error_codes]") {
    CHECK(max_retry_attempts(9999) == 0);
}

// ── category_name ───────────────────────────────────────────────────────────

TEST_CASE("ErrorCodes: category_name returns correct strings", "[error_codes]") {
    CHECK(category_name(ErrorCategory::Plugin) == "Plugin");
    CHECK(category_name(ErrorCategory::Transport) == "Transport");
    CHECK(category_name(ErrorCategory::Orchestration) == "Orchestration");
    CHECK(category_name(ErrorCategory::Agent) == "Agent");
    CHECK(category_name(ErrorCategory::Unknown) == "Unknown");
}
