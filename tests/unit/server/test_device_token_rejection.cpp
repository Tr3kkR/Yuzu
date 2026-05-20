/**
 * test_device_token_rejection.cpp — Wire-boundary collapse + audit/metric
 * expansion contract for `DeviceTokenStore::validate_token` rejections
 * (#1052 + #1053, W1.3).
 *
 * Pins the two halves of the rejection-handling contract:
 *
 *   1. **Wire collapse (#1052).** Every rejection variant — `not_found`,
 *      `revoked`, `expired`, `unbound_legacy`, `binding_mismatch` — must
 *      produce IDENTICAL public output: same HTTP status (401), same
 *      gRPC status (UNAUTHENTICATED), same body envelope, same
 *      `short_message`. The wire side MUST NOT discriminate by variant,
 *      so an attacker holding a stolen valid token cannot distinguish
 *      `binding_mismatch` from `not_found` to confirm token existence.
 *
 *   2. **Audit/metric expansion (#1053).** The operator-visible side —
 *      `rejection_audit_detail_for_storage()` and `rejection_metric_name()` — MUST
 *      discriminate by variant so SRE can alert on a `binding_mismatch`
 *      spike and an auditor can reconstruct attempted impersonations
 *      ("presenter=X bound=Y bound_principal=Z").
 *
 * Latency-band parity (the third leg of #1052's acceptance criterion)
 * is asserted at integration-test scope, not here — unit tests can't
 * reliably measure microsecond-band timing in CI noise. Documented as
 * a follow-up.
 */

#include "device_token_rejection.hpp"
#include "device_token_store.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <set>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

/// Build a `RejectedToken` shaped per the `validate_token` populate-rules
/// for each variant. Hand-rolled rather than driving through the store
/// so this file pins the wire-collapse contract in isolation from the
/// SQLite + binding-enforcement code path (which is exercised in
/// test_device_token_store.cpp).
RejectedToken make_rejected(DeviceTokenValidateError v) {
    RejectedToken r;
    r.error = v;
    switch (v) {
    case DeviceTokenValidateError::invalid_input:
    case DeviceTokenValidateError::not_found:
    case DeviceTokenValidateError::internal_error:
        // no row context — fields stay empty
        break;
    case DeviceTokenValidateError::revoked:
    case DeviceTokenValidateError::expired:
    case DeviceTokenValidateError::binding_mismatch:
        r.token_id = "tok-abc";
        r.bound_device_id = "device-A";
        r.bound_principal_id = "admin";
        break;
    case DeviceTokenValidateError::unbound_legacy:
        // bound_device_id deliberately empty — legacy row has no binding
        r.token_id = "tok-xyz";
        r.bound_principal_id = "admin";
        break;
    }
    return r;
}

const std::vector<DeviceTokenValidateError> kAllVariants = {
    DeviceTokenValidateError::invalid_input,  DeviceTokenValidateError::not_found,
    DeviceTokenValidateError::revoked,        DeviceTokenValidateError::expired,
    DeviceTokenValidateError::unbound_legacy, DeviceTokenValidateError::binding_mismatch,
    DeviceTokenValidateError::internal_error,
};

} // namespace

// ============================================================================
// #1052 — Wire-boundary collapse: identical responses across variants
// ============================================================================

TEST_CASE("device_token_rejection: HTTP envelope identical across all variants",
          "[device_token][wire_collapse][issue1052]") {
    // The make_public_rejection() helper is intentionally variant-free —
    // it cannot differentiate. Pin that contract: calling it for every
    // variant yields the same struct (deep-equal, including envelope JSON).
    auto baseline = make_public_rejection();

    for (auto v : kAllVariants) {
        (void)make_rejected(v); // ensure helper compiles for every enum
        auto p = make_public_rejection();
        CHECK(p.http_status == baseline.http_status);
        CHECK(p.grpc_status == baseline.grpc_status);
        CHECK(p.envelope_json == baseline.envelope_json);
        CHECK(p.short_message == baseline.short_message);
    }

    // Explicit anchor values — surface drift if a future PR adds a
    // variant-aware overload that breaks the contract.
    CHECK(baseline.http_status == 401);
    CHECK(baseline.grpc_status == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(baseline.short_message == "invalid credentials");
}

TEST_CASE("device_token_rejection: envelope JSON shape is the agentic-first envelope",
          "[device_token][wire_collapse][issue1052]") {
    auto p = make_public_rejection();
    auto json = nlohmann::json::parse(p.envelope_json);
    REQUIRE(json.contains("error"));
    REQUIRE(json["error"].is_object());
    CHECK(json["error"].value("code", "") == "invalid_credentials");
    CHECK(json["error"].value("message", "") == "invalid credentials");
    REQUIRE(json.contains("meta"));
    CHECK(json["meta"].value("api_version", "") == "v1");
    // Critical: NO field that varies by variant. The envelope must NOT
    // contain `variant`, `detail`, `bound_device_id`, or anything that
    // could leak the typed reason.
    CHECK(!json["error"].contains("variant"));
    CHECK(!json["error"].contains("detail"));
    CHECK(!json["error"].contains("bound_device_id"));
    CHECK(!json["error"].contains("bound_principal_id"));
    CHECK(!json["error"].contains("token_id"));
}

TEST_CASE("device_token_rejection: gRPC status uniformly UNAUTHENTICATED",
          "[device_token][wire_collapse][issue1052]") {
    auto status = make_grpc_rejection_status();
    CHECK(status.error_code() == grpc::StatusCode::UNAUTHENTICATED);
    // gRPC `error_message` shows up in `status.details()` for clients;
    // must NOT vary by variant, must NOT contain typed-variant strings.
    auto msg = status.error_message();
    CHECK(msg == "invalid credentials");
    CHECK(msg.find("not_found") == std::string::npos);
    CHECK(msg.find("revoked") == std::string::npos);
    CHECK(msg.find("expired") == std::string::npos);
    CHECK(msg.find("unbound_legacy") == std::string::npos);
    CHECK(msg.find("binding_mismatch") == std::string::npos);
    CHECK(msg.find("internal_error") == std::string::npos);
    CHECK(msg.find("device-A") == std::string::npos);
    CHECK(msg.find("admin") == std::string::npos);
}

TEST_CASE("device_token_rejection: typed enum is invisible at wire boundary",
          "[device_token][wire_collapse][issue1052]") {
    // Survey test: walk every variant and confirm the public envelope
    // contains NONE of the operator-visible markers. If a future engineer
    // adds a "helpful" hint to the wire envelope, this test fails first.
    auto baseline = make_public_rejection();
    for (auto v : kAllVariants) {
        auto name = std::string(rejection_variant_name(v));
        REQUIRE_FALSE(name.empty());
        CHECK(baseline.envelope_json.find(name) == std::string::npos);
    }
}

// ============================================================================
// #1053 — Operator-visible expansion (audit detail + Prometheus metrics)
// ============================================================================

TEST_CASE("device_token_rejection: audit detail discriminates by variant",
          "[device_token][audit][issue1053]") {
    // The operator-facing surface MUST distinguish variants — same rule
    // (SOC 2 CC7.2/CC7.3) that requires uniform wire response also
    // requires attributable audit logs.
    std::set<std::string> detail_set;
    for (auto v : kAllVariants) {
        auto rt = make_rejected(v);
        auto detail = rejection_audit_detail_for_storage(rt, "device-B");
        REQUIRE_FALSE(detail.empty());
        CHECK(detail.find(std::string(rejection_variant_name(v))) != std::string::npos);
        detail_set.insert(detail);
    }
    // Every variant must produce a distinct audit detail string.
    CHECK(detail_set.size() == kAllVariants.size());
}

TEST_CASE("device_token_rejection: binding_mismatch audit detail names presenter, bound device, "
          "and bound principal",
          "[device_token][audit][issue1053]") {
    // The #1053 acceptance case: auditor sees the full impersonation
    // attempt without joining additional tables.
    auto rt = make_rejected(DeviceTokenValidateError::binding_mismatch);
    auto detail = rejection_audit_detail_for_storage(rt, "device-B");
    CHECK(detail.find("binding_mismatch") != std::string::npos);
    CHECK(detail.find("presenter=device-B") != std::string::npos);
    CHECK(detail.find("bound=device-A") != std::string::npos);
    CHECK(detail.find("bound_principal=admin") != std::string::npos);
    CHECK(detail.find("token_id=tok-abc") != std::string::npos);
}

TEST_CASE("device_token_rejection: unbound_legacy audit detail omits bound_device_id",
          "[device_token][audit][issue1053]") {
    // Per RejectedToken doc — unbound_legacy MUST NOT carry a fabricated
    // bound_device_id. The legacy row has no binding by construction.
    auto rt = make_rejected(DeviceTokenValidateError::unbound_legacy);
    auto detail = rejection_audit_detail_for_storage(rt, "device-Z");
    CHECK(detail.find("unbound_legacy") != std::string::npos);
    CHECK(detail.find("presenter=device-Z") != std::string::npos);
    CHECK(detail.find("bound_principal=admin") != std::string::npos);
    CHECK(detail.find("token_id=tok-xyz") != std::string::npos);
    // bound=... must NOT appear — empty bound_device_id is suppressed
    CHECK(detail.find(" bound=") == std::string::npos);
}

TEST_CASE("device_token_rejection: not_found audit detail carries no row context",
          "[device_token][audit][issue1053]") {
    // not_found is the only rejection without a row — must not fabricate
    // token_id / bound_* fields.
    auto rt = make_rejected(DeviceTokenValidateError::not_found);
    auto detail = rejection_audit_detail_for_storage(rt, "device-Z");
    CHECK(detail.find("not_found") != std::string::npos);
    CHECK(detail.find("presenter=device-Z") != std::string::npos);
    CHECK(detail.find("token_id=") == std::string::npos);
    CHECK(detail.find(" bound=") == std::string::npos);
    CHECK(detail.find("bound_principal=") == std::string::npos);
}

TEST_CASE("device_token_rejection: internal_error audit detail carries no row context",
          "[device_token][audit][issue1056]") {
    // internal_error (a store-internal fault, e.g. sqlite3_prepare_v2 failure)
    // has no row — like not_found it MUST NOT fabricate token_id / bound_* fields.
    auto rt = make_rejected(DeviceTokenValidateError::internal_error);
    auto detail = rejection_audit_detail_for_storage(rt, "device-Z");
    CHECK(detail.find("internal_error") != std::string::npos);
    CHECK(detail.find("presenter=device-Z") != std::string::npos);
    CHECK(detail.find("token_id=") == std::string::npos);
    CHECK(detail.find(" bound=") == std::string::npos);
    CHECK(detail.find("bound_principal=") == std::string::npos);
}

TEST_CASE("device_token_rejection: Prometheus metric names are stable + variant-discriminated",
          "[device_token][metrics][issue1054][issue1053]") {
    // Three high-signal variants get their own counter (task spec).
    // Others bucket under a single low-signal counter.
    CHECK(rejection_metric_name(DeviceTokenValidateError::binding_mismatch) ==
          "yuzu_device_token_binding_mismatch_total");
    CHECK(rejection_metric_name(DeviceTokenValidateError::unbound_legacy) ==
          "yuzu_device_token_unbound_legacy_total");
    CHECK(rejection_metric_name(DeviceTokenValidateError::revoked) ==
          "yuzu_device_token_revoked_attempt_total");

    // Low-signal bucket
    CHECK(rejection_metric_name(DeviceTokenValidateError::not_found) ==
          "yuzu_device_token_rejected_total");
    CHECK(rejection_metric_name(DeviceTokenValidateError::expired) ==
          "yuzu_device_token_rejected_total");
    CHECK(rejection_metric_name(DeviceTokenValidateError::invalid_input) ==
          "yuzu_device_token_rejected_total");
    CHECK(rejection_metric_name(DeviceTokenValidateError::internal_error) ==
          "yuzu_device_token_rejected_total");
}

TEST_CASE("device_token_rejection: audit event action is a stable single string",
          "[device_token][audit][issue1053]") {
    // Operators searching the audit store for "credential rejection" can
    // filter on this single action — the variant moves into `detail`.
    CHECK(rejection_event_action() == "device_token.validate_failed");
}

TEST_CASE("device_token_rejection: variant names are label-safe",
          "[device_token][metrics][issue1053]") {
    // rejection_variant_name() values are used as Prometheus label
    // values without escaping. Reject any character that would break
    // the exposition format (`:`, `=`, ` `, `"`, `\n`).
    for (auto v : kAllVariants) {
        auto name = std::string(rejection_variant_name(v));
        REQUIRE_FALSE(name.empty());
        CHECK(name.find(':') == std::string::npos);
        CHECK(name.find('=') == std::string::npos);
        CHECK(name.find(' ') == std::string::npos);
        CHECK(name.find('"') == std::string::npos);
        CHECK(name.find('\n') == std::string::npos);
    }
}
