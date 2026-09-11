#include "gateway_service_impl.hpp"

#include <chrono>

#include <nlohmann/json.hpp>

#include "agent_service_impl.hpp"
#include "analytics_event_store.hpp"
#include "audit_store.hpp"
#include "enrollment_token_rejection.hpp"
#include "fleet_topology_store.hpp"
#include "grpc_audit_signal.hpp"
#include "grpc_on_behalf_enforce.hpp"
#include "guaranteed_state_store.hpp"
#include "app_perf_daily_store.hpp"
#include "app_perf_ingestion.hpp"
#include "device_ci_ingestion.hpp"
#include "typed_inventory_sources.hpp"
#include "guardian_ingest.hpp"
#include "heartbeat_ingestion.hpp"
#include "inventory_ingestion.hpp"
#include "inventory_store.hpp"
#include "management_group_store.hpp"
#include "software_inventory_store.hpp"
#include "software_licensing_ingestion.hpp"
#include "software_licensing_store.hpp"
#include "peer_ip.hpp"

namespace yuzu::server::detail {

namespace {

// HA WS-4 slice 4.1: lease TTL for GatewayRouteStore rows. The gateway's own
// heartbeat-forwarding cadence batches on a ~1s flush interval
// (gateway/config/sys.config's heartbeat_batch_interval_ms), but the
// underlying signal this lease must survive is the AGENT's own heartbeat
// interval — default 30s (agents/core/include/yuzu/agent/agent.hpp,
// Config::heartbeat_interval) — since BatchHeartbeat's renew_leases call
// below only fires once per agent heartbeat. 3x that (90s) tolerates a
// couple of missed heartbeats without the route reading stale; INERT this
// slice (nothing reads is_stale yet) but the margin is chosen now so a
// future reader doesn't inherit an accidentally-tight TTL.
constexpr int kGatewayRouteLeaseTtlSecs = 90;

// HA WS-4 slice 4.1: fail-OPEN observability for the (write-only, INERT)
// gateway route directory (gateway_route_store.hpp). A degraded write here
// NEVER fails the RPC — nothing reads this store for dispatch yet — but IS
// logged and counted so a systemic Postgres problem is visible before any
// future reader ever depends on this data being fresh.
void record_route_store_failure(yuzu::MetricsRegistry* metrics, std::string_view op,
                                GatewayRouteStoreError err) {
    const char* reason =
        err == GatewayRouteStoreError::store_unavailable ? "store_unavailable" : "db_error";
    spdlog::warn("[gateway] GatewayRouteStore {} degraded ({}) — proceeding (directory write is "
                 "fail-open, INERT this slice: nothing reads it for dispatch yet)",
                 op, reason);
    if (metrics) {
        metrics
            ->counter("yuzu_server_gateway_route_write_failed_total",
                      {{"op", std::string(op)}, {"reason", reason}})
            .increment();
    }
}

// WS-4 4.2a #8 — guard-no-op / directory-desync visibility. A guard (the
// session-scoped WHERE clauses in announce_connected/deregister/renew_leases,
// and NotifyStreamStatus's own gateway_sessions_ lookup) rejecting a write is
// NOT a store failure — the call succeeded, the store correctly refused to
// touch a row it doesn't own. That refusal is exactly the "systemic desync"
// signal an operator needs visibility into (in-memory gateway_sessions_ vs.
// the durable directory row disagreeing about which session currently owns
// an agent's route), separate from record_route_store_failure's degraded-I/O
// signal above. `count` lets a batched caller (renew_leases' shortfall)
// report magnitude in one increment instead of one call per missing row.
//
// Deliberately EXCLUDED from this counter: a `register_fresh` epoch-race
// loss (RegisterFreshResult::won == false). That is an expected, benign
// outcome of concurrent connects for the SAME agent — see the ProxyRegister
// `lost_race_sessions_` bookkeeping below, which skips the FOLLOW-UP
// announce_connected call entirely for a losing session so it never reaches
// this counter as a false "session_mismatch" desync.
void record_directory_desync(yuzu::MetricsRegistry* metrics, std::string_view op,
                             std::string_view outcome, double count = 1.0) {
    spdlog::warn("[gateway] GatewayRouteStore {} guard rejected the write (outcome={}, count={}) "
                 "— directory may be out of sync with the in-memory session map",
                 op, outcome, count);
    if (metrics) {
        metrics
            ->counter("yuzu_server_gateway_route_desync_total",
                      {{"op", std::string(op)}, {"outcome", std::string(outcome)}})
            .increment(count);
    }
}

} // namespace

// -- Constructor --------------------------------------------------------------

GatewayUpstreamServiceImpl::GatewayUpstreamServiceImpl(AgentRegistry& registry, EventBus& bus,
                                                       auth::AuthManager& auth_mgr,
                                                       auth::AutoApproveEngine& auto_approve,
                                                       yuzu::MetricsRegistry* metrics,
                                                       AgentHealthStore* health_store)
    : registry_(registry), bus_(bus), auth_mgr_(auth_mgr), auto_approve_(auto_approve),
      metrics_(metrics), health_store_(health_store) {
    if (metrics_) {
        metrics_->describe(
            "yuzu_server_gateway_route_write_failed_total",
            "HA WS-4 4.1: GatewayRouteStore directory writes (register_fresh/"
            "announce_connected/deregister/renew_leases) that degraded instead of "
            "succeeding, by op and reason. Fail-OPEN this slice - the RPC proceeds "
            "regardless, since nothing reads this store for dispatch yet - so this "
            "counter is the only signal a systemic write failure would otherwise "
            "leave invisible.",
            "counter");
        metrics_->describe(
            "yuzu_server_gateway_route_desync_total",
            "HA WS-4 4.2a: GatewayRouteStore session-guard writes (announce_connected/"
            "deregister/renew_leases) that succeeded but matched/renewed zero rows for the "
            "presented session, plus NotifyStreamStatus's own unknown-session reject, by op "
            "and outcome. A guard rejection is EXPECTED at a low background rate (stale/"
            "superseded-session notifications the guards exist to no-op on) — a sustained rise "
            "is the signal that the in-memory session map and the durable directory have gone "
            "out of sync. A register_fresh epoch-race LOSS is deliberately excluded (see the "
            "lost_race_sessions_ bookkeeping) so a benign concurrent-connect race never inflates "
            "this counter.",
            "counter");
    }
}

// -- ProxyRegister ------------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::ProxyRegister(grpc::ServerContext* context,
                                                       const pb::RegisterRequest* request,
                                                       pb::RegisterResponse* response) {
    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp. Must run
    // before any side effect below (audit, auth-mgr lookup, registry write).
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    const auto& info = request->info();

    // #1064: on this path the transport peer is the GATEWAY's IP, not the
    // agent's — so an audit row keyed on `context->peer()` mis-attributes the
    // source (SOC 2 IR-2; SIEM "race-loss IP must equal winner IP" false
    // negatives). Prefer the gateway-observed agent origin IP carried in the
    // RegisterRequest (a bare IP the gateway fills; empty under transports that
    // can't observe the agent peer — see the proto field comment), validated
    // through the same strict parser as direct peers. Fall back to the gateway
    // IP when absent, recording origin_observed=false so an auditor knows the
    // source_ip is the relay, not the agent. Both IPs go in `detail`.
    const std::string gateway_ip = context ? extract_peer_ip(context->peer()) : std::string{};
    const std::string observed_origin =
        ::yuzu::server::detail::normalize_bare_ip(request->gateway_observed_peer());
    const std::string agent_source_ip = observed_origin.empty() ? gateway_ip : observed_origin;
    // Capture by value (gov Hermes SEC-07): defensive against a future refactor
    // that stores/returns the lambda — the captured strings then can't dangle.
    const auto append_origin_detail = [gateway_ip, observed_origin](std::string& detail) {
        detail.append(" gateway_ip=").append(gateway_ip);
        if (observed_origin.empty())
            detail.append(" origin_observed=false");
    };

    // -- W1.4 R2 / UP-H1 agent_id length bound (mirror of direct Register) ----
    // Same rationale as the direct-connect path in AgentServiceImpl::Register
    // — cap before any audit emission, auth-mgr lookup, or SHA-256. Source
    // label on the metric is `gateway_proxy` so SRE can see attacks coming
    // through the gateway vs direct-connect agents.
    if (info.agent_id().empty() || info.agent_id().size() > auth::kMaxAgentIdLength) {
        spdlog::warn(
            "[gateway] ProxyRegister rejected: agent_id length {} (max {}, empty disallowed)",
            info.agent_id().size(), auth::kMaxAgentIdLength);
        if (metrics_) {
            metrics_
                ->counter("yuzu_register_invalid_agent_id_total",
                          {{"reason", "length"}, {"source", "gateway_proxy"}})
                .increment();
        }
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "agent_id length exceeds 256 chars or empty");
    }

    // -- Tiered enrollment (same logic as AgentServiceImpl::Register) ----------
    //
    // W1.3 R2 / UP-7 / sec-G MEDIUM-1: trusted-peer noting moved to the
    // success path below (after `gw_enrolled:`). The prior implementation
    // recorded the peer BEFORE the enrollment branches with the rationale
    // that denied enrollments still contribute to gateway-trust discovery.
    // That inverts the trust model: any peer that can reach :50055 with
    // ANY ProxyRegister payload (forged enrollment token, garbage agent_id,
    // anything that fails token validation or admin denial) would become
    // trusted for the rest of the process lifetime.
    //
    // The trusted-set is now populated ONLY when the proxy enrollment
    // succeeds. The set still assumes the gateway-upstream listener (:50055)
    // is itself authenticated via TLS/mTLS at the operator's network
    // boundary — without that, an attacker who reaches the port AND knows
    // a valid enrollment token could still add themselves; the post-PR-3
    // native-QUIC redesign tightens this with mandatory peer-cert pinning.

    // Fast path: agent already enrolled from a prior connection
    {
        auto prior = auth_mgr_.get_pending_status(info.agent_id());
        if (prior && *prior == auth::PendingStatus::approved) {
            spdlog::info("[gateway] Agent {} re-registering (already enrolled)", info.agent_id());
            goto gw_enrolled;
        }
        // #1067: reject an admin-DENIED agent BEFORE consuming any enrollment
        // token — same token-depletion DoS as the direct-connect path (W1.4
        // UP-M3). The gateway proxies the agent's RegisterRequest unmodified, so
        // this path is equally reachable; mirror the direct fix here.
        if (prior && *prior == auth::PendingStatus::denied) {
            // gov #1134: bounded denied-attempt signal (mirror of the direct
            // Register path). A counter, not an audit row (DoS-safe under a
            // denied flood). event=security routes it to the SIEM. metrics_ is
            // null-guarded (optional on this service).
            if (metrics_) {
                metrics_
                    ->counter("yuzu_register_denied_total",
                              {{"source", "gateway_proxy"}, {"event", "security"}})
                    .increment();
            }
            spdlog::warn("[gateway] Register rejected: agent {} is admin-denied (no token consumed)",
                         info.agent_id());
            response->set_accepted(false);
            response->set_reject_reason("enrollment denied by administrator");
            response->set_enrollment_status("denied");
            return grpc::Status::OK;
        }
    }

    {
        const auto& enrollment_token = request->enrollment_token();

        if (!enrollment_token.empty()) {
            // -- W1.1 UP-H2 length bound (mirrored from the direct path) ------
            if (enrollment_token.size() > auth::kMaxEnrollmentTokenLength) {
                spdlog::warn(
                    "[gateway] Agent {} presented oversize enrollment token ({} chars > {})",
                    info.agent_id(), enrollment_token.size(), auth::kMaxEnrollmentTokenLength);
                if (metrics_) {
                    metrics_
                        ->counter("yuzu_enrollment_token_rejected_total",
                                  {{"variant", "invalid_input_length"}})
                        .increment();
                }
                if (auto analytics_store = analytics_store_.lock()) {
                    AnalyticsEvent ae;
                    ae.event_type = "agent.enrollment_denied";
                    ae.agent_id = info.agent_id();
                    ae.hostname = info.hostname();
                    ae.os = info.platform().os();
                    ae.arch = info.platform().arch();
                    ae.severity = Severity::kWarn;
                    ae.attributes = {{"reason", "invalid_input_length"},
                                     {"token_length", enrollment_token.size()},
                                     {"source", "gateway_proxy"}};
                    analytics_store->emit(std::move(ae));
                }
                response->set_accepted(false);
                response->set_reject_reason(
                    std::string(yuzu::server::kEnrollmentTokenRejectionPublicMessage));
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }

            // -- W1.4 / #827 atomic consume (mirror of AgentServiceImpl) ------
            auto claim_result =
                auth_mgr_.consume_enrollment_token(enrollment_token, info.agent_id());
            if (!claim_result.has_value()) {
                auto err = claim_result.error();
                auto variant = yuzu::server::enrollment_rejection_variant_name(err);
                auto metric_name = yuzu::server::enrollment_rejection_metric_name(err);
                spdlog::warn("[gateway] Agent {} enrollment-token consume rejected: variant={}",
                             info.agent_id(), variant);
                if (metrics_) {
                    if (err == auth::EnrollmentTokenError::already_consumed) {
                        metrics_->counter(std::string(metric_name), {}).increment();
                    } else {
                        metrics_
                            ->counter(std::string(metric_name), {{"variant", std::string(variant)}})
                            .increment();
                    }
                }

                std::string already_consumed_by;
                if (err == auth::EnrollmentTokenError::already_consumed) {
                    auto hash = auth::AuthManager::sha256_hex(enrollment_token);
                    already_consumed_by = auth_mgr_.last_consumer_for_token_hash(hash);
                }

                bool audit_ok = true;
                if (audit_store_ && audit_store_->is_open()) {
                    AuditEvent ev;
                    ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
                    ev.principal = "agent:" + info.agent_id();
                    ev.principal_role = "agent";
                    ev.action = std::string(yuzu::server::enrollment_event_action());
                    ev.target_type = "enrollment_token";
                    auto hash_for_audit = auth::AuthManager::sha256_hex(enrollment_token);
                    ev.target_id = hash_for_audit.substr(0, 8);
                    std::string detail = std::string("variant=")
                                             .append(variant)
                                             .append(" presenter=")
                                             .append(info.agent_id())
                                             .append(" source=gateway_proxy");
                    if (!already_consumed_by.empty()) {
                        detail.append(" already_consumed_by=").append(already_consumed_by);
                    }
                    append_origin_detail(detail); // #1064: gateway_ip + origin_observed
                    ev.detail = std::move(detail);
                    ev.source_ip = agent_source_ip; // #1064: agent origin, not gateway IP
                    ev.result = "failure";
                    audit_ok = audit_store_->log(ev);
                }

                // #1063: surface a dropped audit row on the wire (mirror REST
                // Sec-Audit-Failed) so the operator sees the evidence-chain gap.
                if (!audit_ok)
                    signal_grpc_audit_failed(context);

                if (auto analytics_store = analytics_store_.lock()) {
                    AnalyticsEvent ae;
                    ae.event_type = "agent.enrollment_denied";
                    ae.agent_id = info.agent_id();
                    ae.hostname = info.hostname();
                    ae.os = info.platform().os();
                    ae.arch = info.platform().arch();
                    if (err == auth::EnrollmentTokenError::already_consumed || !audit_ok) {
                        ae.severity = Severity::kError;
                    } else {
                        ae.severity = Severity::kWarn;
                    }
                    nlohmann::json attrs = {{"reason", std::string(variant)},
                                            {"audit_emitted", audit_ok},
                                            {"source", "gateway_proxy"}};
                    if (!already_consumed_by.empty()) {
                        attrs["already_consumed_by"] = already_consumed_by;
                    }
                    ae.attributes = std::move(attrs);
                    analytics_store->emit(std::move(ae));
                }

                response->set_accepted(false);
                response->set_reject_reason(
                    std::string(yuzu::server::kEnrollmentTokenRejectionPublicMessage));
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }
            const auto& claim = claim_result.value();
            spdlog::info("[gateway] Agent {} auto-enrolled via enrollment token id={} ({}/{})",
                         info.agent_id(), claim.token_id, claim.use_count_after,
                         claim.max_uses == 0 ? -1 : claim.max_uses);

            bool enroll_audit_ok = true;
            if (audit_store_ && audit_store_->is_open()) {
                AuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                ev.principal = "agent:" + info.agent_id();
                ev.principal_role = "agent";
                ev.action = std::string(yuzu::server::enrollment_event_action());
                ev.target_type = "enrollment_token";
                ev.target_id = claim.token_id;
                std::string detail =
                    std::string("variant=success source=gateway_proxy use_count=")
                        .append(std::to_string(claim.use_count_after))
                        .append("/")
                        .append(claim.max_uses == 0 ? std::string{"unlimited"}
                                                    : std::to_string(claim.max_uses));
                append_origin_detail(detail); // #1064: gateway_ip + origin_observed
                ev.detail = std::move(detail);
                ev.source_ip = agent_source_ip; // #1064: agent origin, not gateway IP
                ev.result = "success";
                enroll_audit_ok = audit_store_->log(ev);
            }
            // #1065 / #1063: a dropped SUCCESS audit row is the same
            // evidence-chain degradation as a dropped failure row — was
            // fire-and-forget. Surface on the wire and escalate analytics,
            // mirroring the denial path's audit_ok handling. SOC 2 CC7.2.
            if (!enroll_audit_ok) {
                signal_grpc_audit_failed(context);
                if (auto analytics_store = analytics_store_.lock()) {
                    AnalyticsEvent ae;
                    ae.event_type = "agent.enrollment_audit_dropped";
                    ae.agent_id = info.agent_id();
                    ae.hostname = info.hostname();
                    ae.os = info.platform().os();
                    ae.arch = info.platform().arch();
                    ae.severity = Severity::kError;
                    ae.attributes = {{"result", "success"},
                                     {"audit_emitted", false},
                                     {"source", "gateway_proxy"}};
                    analytics_store->emit(std::move(ae));
                }
            }

            if (!auth_mgr_.ensure_enrolled(info.agent_id(), info.hostname(), info.platform().os(),
                                           info.platform().arch(), info.agent_version())) {
                response->set_accepted(false);
                response->set_reject_reason("enrollment denied by administrator");
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }
        } else {
            // Auto-approve policies (no peer IP available from gateway yet)
            auth::ApprovalContext approval_ctx;
            approval_ctx.hostname = info.hostname();
            approval_ctx.attestation_provider = request->attestation_provider();

            auto matched_rule = auto_approve_.evaluate(approval_ctx);
            if (!matched_rule.empty()) {
                spdlog::info("[gateway] Agent {} auto-approved by policy: {}", info.agent_id(),
                             matched_rule);
                if (!auth_mgr_.ensure_enrolled(info.agent_id(), info.hostname(),
                                               info.platform().os(), info.platform().arch(),
                                               info.agent_version())) {
                    response->set_accepted(false);
                    response->set_reject_reason("enrollment denied by administrator");
                    response->set_enrollment_status("denied");
                    return grpc::Status::OK;
                }
            } else {
                // Tier 1: pending queue
                auto pending_status = auth_mgr_.get_pending_status(info.agent_id());

                if (!pending_status) {
                    auth_mgr_.add_pending_agent(info.agent_id(), info.hostname(),
                                                info.platform().os(), info.platform().arch(),
                                                info.agent_version());

                    response->set_accepted(false);
                    response->set_reject_reason("awaiting admin approval");
                    response->set_enrollment_status("pending");
                    bus_.publish("pending-agent", info.agent_id());
                    spdlog::info("[gateway] Agent {} placed in pending queue", info.agent_id());
                    return grpc::Status::OK;
                }

                switch (*pending_status) {
                case auth::PendingStatus::pending:
                    response->set_accepted(false);
                    response->set_reject_reason("still awaiting admin approval");
                    response->set_enrollment_status("pending");
                    return grpc::Status::OK;
                case auth::PendingStatus::denied:
                    response->set_accepted(false);
                    response->set_reject_reason("enrollment denied by administrator");
                    response->set_enrollment_status("denied");
                    return grpc::Status::OK;
                case auth::PendingStatus::approved:
                    spdlog::info("[gateway] Agent {} enrolled (admin-approved)", info.agent_id());
                    break;
                }
            }
        }
    } // end enrollment checks

gw_enrolled:
    // -- Enrolled -- register the agent ----------------------------------------
    //
    // W1.3 R2 / UP-7: trust-after-auth. Only record the gateway's peer IP
    // in the trusted set AFTER enrollment succeeds. Re-registration (fast
    // path at the top of the function) also lands here, so a gateway that
    // re-proxies an already-enrolled agent keeps refreshing the trust
    // entry — exactly the lifetime the TTL eviction (UP-2 / UP-3) expects.
    if (context) {
        registry_.note_trusted_gateway_peer(extract_peer_ip(context->peer()));
    }

    // #3401 Gap 2: register_agent fails closed if the W1.5/#823 device-token revoke sweep
    // itself errors. Note the peer trust note above already ran — a store fault does not
    // un-trust the gateway peer (that entry has its own TTL eviction, UP-2/UP-3); only the
    // agent's own registration is refused. UNAVAILABLE, not accepted=false (the agent's
    // PERMANENT-rejection signal, agent.cpp:1649-1657), so the agent retries on its normal
    // reconnect backoff.
    if (auto reg_result = registry_.register_agent(info); !reg_result) {
        spdlog::error("ProxyRegister: register_agent failed for '{}': {}", info.agent_id(),
                      reg_result.error());
        return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                            "registration temporarily unavailable");
    }
    // Auto-add to root management group
    if (mgmt_group_store_ && mgmt_group_store_->is_open())
        mgmt_group_store_->add_member(ManagementGroupStore::kRootGroupId, info.agent_id());

    // HA WS-4 4.1 (routed-concern: gateway routing directory): a gateway
    // circuit-recovery replay resends ProxyRegister carrying the ORIGINAL
    // session id in the x-yuzu-session-id metadata — the same key + reader
    // AgentServiceImpl::Subscribe uses on the direct path, reused here so
    // the two paths cannot silently drift onto different metadata keys.
    // Only trust it as a re-announce if that session is STILL known
    // server-side (belt-and-braces against a forged/stale value); anything
    // else falls through to minting a fresh session exactly as before.
    std::string presented_session;
    if (context) {
        presented_session = AgentServiceImpl::client_metadata_value(
            *context, AgentServiceImpl::kSessionMetadataKey);
    }
    bool presented_session_known = false;
    if (!presented_session.empty()) {
        std::lock_guard lock(sessions_mu_);
        auto it = gateway_sessions_.find(presented_session);
        presented_session_known = it != gateway_sessions_.end() && it->second == info.agent_id();
    }

    std::string session_id;
    bool lost_epoch_race = false;
    if (presented_session_known) {
        // -- Re-announce: reuse the caller's still-known session -------------
        //
        // Architecture-review decision (HA WS-4 4.1): minting a fresh
        // session+epoch here would let a delayed/zombie replay of an OLDER
        // connection's ProxyRegister clobber the route a NEWER connection
        // already won — the epoch fence in gateway_route_store.hpp exists
        // precisely to stop that, and register_fresh must therefore NOT be
        // called on this branch. Reusing the presented session also fixes
        // the pre-existing S'-vs-S session-mismatch this replay case had:
        // the response and the in-proc `gateway_sessions_`/registry mapping
        // now agree with the session the gateway actually holds.
        session_id = presented_session;
        if (gateway_route_store_) {
            std::vector<std::string> renew_ids{session_id};
            if (auto res = gateway_route_store_->renew_leases(renew_ids, kGatewayRouteLeaseTtlSecs);
                !res) {
                record_route_store_failure(metrics_, "renew_leases", res.error());
            } else if (*res < static_cast<int>(renew_ids.size())) {
                record_directory_desync(metrics_, "renew_leases", "shortfall",
                                        static_cast<double>(renew_ids.size() - *res));
            }
        }
        spdlog::debug("[gateway] ProxyRegister: re-announcing known session {} for agent {}",
                     session_id, info.agent_id());
    } else if (!presented_session.empty()) {
        // -- 4.2a #2 (mechanism c): presented but UNKNOWN locally -------------
        //
        // A non-empty x-yuzu-session-id this replica's `gateway_sessions_`
        // doesn't recognize is either a replica restart (the durable
        // directory row may still be current — this replica just lost its
        // in-memory map), a cross-replica delivery, or a genuinely stale/
        // zombie replay whose session has since been superseded. Either way
        // `register_fresh` must NEVER run here: it would mint a fresh epoch
        // and unconditionally win (register_fresh's guarded UPSERT only
        // fences CONCURRENT registrations, not a stale replay processed
        // later — see gateway_route_store.hpp's "4.2 OBLIGATIONS" note),
        // silently clobbering a live newer connection's route.
        //
        // Instead, renew the PRESENTED session (not the freshly-minted
        // session_id below): if the durable row still belongs to it, the
        // renew matches and the lease is correctly extended with no epoch
        // change. If it's a zombie (the row now belongs to a different,
        // newer session), the renew matches zero rows — counted below as a
        // desync signal — and nothing is clobbered.
        //
        // SCOPE LIMIT (deferred to #6/4.4): the in-memory gateway_sessions_
        // entry and the session_id returned to the caller below are left
        // UNCHANGED from the pre-4.2a "fresh" behavior — a new session_id is
        // still minted and returned. That means the response's session_id
        // (S') and the directory row this branch may have just renewed
        // (still keyed on the presented S) can disagree; closing that
        // S'-vs-S gap is out of scope for this slice (directory writes
        // only).
        if (gateway_route_store_) {
            std::vector<std::string> renew_ids{presented_session};
            if (auto res = gateway_route_store_->renew_leases(renew_ids, kGatewayRouteLeaseTtlSecs);
                !res) {
                record_route_store_failure(metrics_, "renew_leases", res.error());
            } else if (*res < static_cast<int>(renew_ids.size())) {
                record_directory_desync(metrics_, "renew_leases", "shortfall",
                                        static_cast<double>(renew_ids.size() - *res));
            }
        }
        spdlog::debug("[gateway] ProxyRegister: presented session {} for agent {} is unknown "
                     "locally — renewed the presented session in the directory instead of "
                     "minting a fresh epoch",
                     presented_session, info.agent_id());
        // Session-id minting and gateway_sessions_ population are UNCHANGED
        // from the pre-4.2a behavior (deferred S'-vs-S fix, see above) —
        // NO register_fresh call on this branch, per the mechanism-(c)
        // contract: "never register_fresh" when a presented session is
        // unknown locally.
        session_id =
            "gw-session-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
    } else {
        // -- Fresh registration (unchanged behavior) --------------------------
        session_id =
            "gw-session-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
        if (gateway_route_store_) {
            if (auto res = gateway_route_store_->register_fresh(info.agent_id(), session_id);
                !res) {
                record_route_store_failure(metrics_, "register_fresh", res.error());
            } else if (!res->won) {
                // A newer connection's register_fresh already won the epoch race
                // (out-of-order delivery, gateway_route_store.hpp). Inert this
                // slice — nothing dispatches through this store yet — so just
                // note it; this session still enrolls and connects normally.
                // 4.2a #8: recorded in lost_race_sessions_ below so the
                // FOLLOW-UP NotifyStreamStatus CONNECTED for this session
                // skips announce_connected instead of reporting a false
                // "session_mismatch" desync (see record_directory_desync's
                // header comment).
                lost_epoch_race = true;
                spdlog::debug("[gateway] ProxyRegister: register_fresh for agent {} session {} "
                              "lost the epoch race to a newer connection",
                              info.agent_id(), session_id);
            }
        }
    }

    response->set_session_id(session_id);
    response->set_accepted(true);
    response->set_enrollment_status("enrolled");

    // PR5d: mirror the direct Register path — if the agent sent a CSR and the
    // signer is wired (CA active), sign a per-agent client leaf bound to agent_id
    // and return it. Before this, a gateway-enrolled agent registered fine but
    // never received a per-agent cert (only the direct AgentServiceImpl::Register
    // signed), so it retried then degraded to one-way TLS. The agent↔gateway hop
    // is one-way TLS in M1 (PR5c) — the leaf is presented to a non-verifying
    // listener for now — but issuing it completes per-agent-mTLS-day-one (D4),
    // records the cert in ca_issued for inventory/revocation, and future-proofs
    // gateway mTLS. The Erlang gateway relays the RegisterResponse verbatim
    // (yuzu_gw_agent_service:register/2), so issued_certificate flows to the agent
    // (gateway_pb/agent_pb carry the fields since PR5). Signing failure is
    // non-fatal — the agent stays on the bootstrap posture and retries.
    //
    // Gate parity with the direct path (intentional): we only reach gw_enrolled
    // after enrollment succeeded (denied/pending agents returned early above; the
    // re-register fast-path reaches here only for an already-APPROVED agent). Like
    // the direct path, issuance is NOT gated on cert revocation — revoke is
    // serial-scoped (it invalidates a presented leaf); DENYING the agent is what
    // stops re-enrollment/re-issuance (checked above). The shared signer
    // (sign_agent_csr) carries the per-agent rate-limit + CSR-size cap, so both
    // paths share one issuance chokepoint and cannot drift.
    if (!request->csr_pem().empty() && agent_cert_signer_) {
        // #1273 B-2: the signer (sign_agent_csr) runs INSIDE this synchronous gRPC
        // handler and is now reachable over the one-way-TLS gateway edge. An
        // exception out of it (OpenSSL error, bad_alloc, …) would propagate out of
        // the sync handler and terminate the server. Contain it and degrade to
        // no-cert (identical to a nullopt return — the agent stays on bootstrap).
        std::optional<std::pair<std::string, std::string>> issued;
        try {
            issued = agent_cert_signer_(request->csr_pem(), info.agent_id(),
                                        CertIssuanceSource::GatewayProxy);
        } catch (const std::exception& e) {
            spdlog::error("[gateway] ProxyRegister: signer threw for agent {}: {}",
                          info.agent_id(), e.what());
        } catch (...) {
            // Non-std throw (foreign exception across a plugin/.so boundary, etc.)
            // must not escape the sync handler either (gov #1273 Hermes).
            spdlog::error("[gateway] ProxyRegister: signer threw a non-std exception for agent {}",
                          info.agent_id());
        }
        if (issued) {
            response->set_issued_certificate(issued->first);
            response->set_issued_ca_chain(issued->second);
            spdlog::info("[gateway] Issued per-agent client cert for {}", info.agent_id());
        } else {
            spdlog::warn("[gateway] ProxyRegister: client-cert signing failed for agent {}",
                         info.agent_id());
        }
    }

    // Store session_id on the AgentSession so session-aware cleanup works.
    // Without this, remove_agent_if_session would always no-op for gateway agents.
    registry_.map_session(session_id, info.agent_id());

    {
        std::lock_guard lock(sessions_mu_);
        gateway_sessions_[session_id] = info.agent_id();
        // 4.2a #8: remember a register_fresh epoch-race loss against ITS
        // session_id so the follow-up NotifyStreamStatus CONNECTED can skip
        // announce_connected instead of reporting a benign race-loss as a
        // desync (see record_directory_desync's header comment). A session
        // that reaches this line via the re-announce or unknown-session
        // branches never had lost_epoch_race set, so this is a plain insert,
        // never a stale leftover from a prior session reusing this id (a
        // freshly-minted random 128-bit session_id does not collide with an
        // old entry still needing eviction).
        if (lost_epoch_race)
            lost_race_sessions_.insert(session_id);
    }

    spdlog::info("[gateway] ProxyRegister succeeded: agent={}, session={}", info.agent_id(),
                 session_id);
    return grpc::Status::OK;
}

// -- BatchHeartbeat -----------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::BatchHeartbeat(grpc::ServerContext* context,
                                                        const gw::BatchHeartbeatRequest* request,
                                                        gw::BatchHeartbeatResponse* response) {
    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    int acked = 0;
    for (const auto& hb : request->heartbeats()) {
        // Validate that the session is known
        std::string agent_id;
        {
            std::lock_guard lock(sessions_mu_);
            auto it = gateway_sessions_.find(hb.session_id());
            if (it != gateway_sessions_.end()) {
                agent_id = it->second;
            }
        }
        if (agent_id.empty()) {
            spdlog::debug("[gateway] BatchHeartbeat: unknown session {}", hb.session_id());
            continue;
        }
        // #1000 / arch-S2: shared HeartbeatIngestion keeps the per-heartbeat
        // work (health upsert, metrics, fleet_snapshot push) identical to
        // the direct-heartbeat path so the two cannot drift.
        //
        // Gate 7 UP-10 — per-entry try/catch. A gateway BatchHeartbeat can
        // carry thousands of agents' heartbeats in one RPC; if ingest()
        // throws on a single entry (std::bad_alloc on a near-cap map walk,
        // a malformed payload that slips past the parser's own guard, an
        // exception out of health_store_/metrics_), an unhandled throw
        // would abort the whole RPC handler and silently drop every
        // remaining heartbeat in the batch — a single bad agent could
        // blank a gateway's entire fleet. Isolate each entry.
        if (heartbeat_ingestion_) {
            try {
                heartbeat_ingestion_->ingest(hb, agent_id, "gateway");
            } catch (const std::exception& ex) {
                spdlog::warn("[gateway] BatchHeartbeat: ingest threw for agent {} — "
                             "skipping entry, batch continues: {}",
                             agent_id, ex.what());
                continue;
            } catch (...) {
                spdlog::warn("[gateway] BatchHeartbeat: ingest threw unknown exception for "
                             "agent {} — skipping entry, batch continues",
                             agent_id);
                continue;
            }
        }
        ++acked;
    }

    // HA WS-4 4.1: batch-renew the route lease for every session in this
    // heartbeat batch, in ONE call (gateway_route_store.hpp's renew_leases is
    // itself a single batched statement) — matches BatchHeartbeat's own
    // batching rather than one write per agent per interval. Collected from
    // the raw request (not gated on "known"/ingest success above): a lease
    // renewal is about session liveness, independent of whether ingest
    // happened to throw on that entry this cycle.
    //
    // Trust rationale (asymmetric with ProxyRegister's known-session gate, by
    // design): renew matches on session_id ALONE, with no agent_id correlation
    // or gateway_sessions_ membership check. This is defense-in-depth only, not
    // a hole in the threat model: the gateway upstream is mTLS-authenticated
    // trusted infrastructure, and session_id is a server-minted 128-bit random
    // token, so renewing a foreign session requires a compromised/buggy gateway
    // that also knows that token. A 4.2 hardening option (if the directory
    // becomes dispatch-authoritative) is to correlate agent_id per renewed
    // session; recorded in the ADR-2002 §7 4.2 obligations.
    if (gateway_route_store_) {
        std::vector<std::string> session_ids;
        session_ids.reserve(static_cast<std::size_t>(request->heartbeats_size()));
        for (const auto& hb : request->heartbeats()) {
            if (!hb.session_id().empty())
                session_ids.push_back(hb.session_id());
        }
        if (!session_ids.empty()) {
            if (auto res =
                    gateway_route_store_->renew_leases(session_ids, kGatewayRouteLeaseTtlSecs);
                !res) {
                record_route_store_failure(metrics_, "renew_leases", res.error());
            } else if (*res < static_cast<int>(session_ids.size())) {
                record_directory_desync(metrics_, "renew_leases", "shortfall",
                                        static_cast<double>(session_ids.size() -
                                                            static_cast<std::size_t>(*res)));
            }
        }
    }

    response->set_acknowledged_count(acked);
    spdlog::debug("[gateway] BatchHeartbeat from node '{}': {}/{} acked", request->gateway_node(),
                  acked, request->heartbeats_size());
    return grpc::Status::OK;
}

// -- ProxyInventory -----------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::ProxyInventory(grpc::ServerContext* context,
                                                        const pb::InventoryReport* request,
                                                        pb::InventoryAck* response) {
    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    std::string agent_id;
    {
        std::lock_guard lock(sessions_mu_);
        auto it = gateway_sessions_.find(request->session_id());
        if (it != gateway_sessions_.end()) {
            agent_id = it->second;
        }
    }
    if (agent_id.empty()) {
        spdlog::warn("[gateway] ProxyInventory: unknown session {}", request->session_id());
        response->set_received(false);
        return grpc::Status::OK;
    }

    // The generic loop runs before the typed seams, so enforce the shared
    // whole-report cap here before any store write or pool acquisition.
    if (!validate_inventory_report_source_count(agent_id, *request, metrics_)) {
        response->set_received(true);
        return grpc::Status::OK;
    }

    // Generic per-source blob persistence (sync-framework baseline; backs the
    // kInventoryQuery scope source + the inventory eval engine). The TYPED sources
    // (installed_software / app_perf / device_ci / software_licensing) are persisted
    // via their own normalized stores + shared seams below — skip them here, or they
    // double-store into the generic InventoryStore. That generic store is read on
    // Infrastructure:Read (query_inventory/get_agent_inventory), so a typed source
    // leaking into it bypasses its own securable AND breaks direct/gateway parity
    // (the direct ReportInventory path has no generic loop). is_typed_inventory_source
    // is the single skip-list — a new typed source registers there (ADR-0016 §5).
    if (inventory_store_ && inventory_store_->is_open()) {
        int64_t collected_epoch = 0;
        if (request->has_collected_at()) {
            collected_epoch = request->collected_at().millis_epoch() / 1000;
        }
        for (const auto& [plugin_name, data_bytes] : request->plugin_data()) {
            if (is_typed_inventory_source(plugin_name))
                continue; // typed projections, handled by their seams below
            std::string json_str(data_bytes.begin(), data_bytes.end());
            inventory_store_->upsert(agent_id, plugin_name, json_str, collected_epoch);
        }
    }
    // Typed installed_software via the shared seam (ADR-0016 §5) — byte-identical
    // to the direct ReportInventory path; fills response->need_full for any
    // source needing a cold-cache resync.
    if (software_inventory_store_ && software_inventory_store_->is_open()) {
        // Isolate ingest failures, identical to the direct ReportInventory path
        // — otherwise an exception escapes as gRPC UNKNOWN (UP-9 / parity).
        try {
            ingest_inventory_report(*software_inventory_store_, agent_id, *request, *response,
                                    metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("[gateway] ProxyInventory: inventory ingest threw for agent={} — acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("[gateway] ProxyInventory: inventory ingest threw (unknown) for agent={} "
                         "— acked",
                         agent_id);
        }
    }
    // Typed app_perf via its shared seam (DEX app-perf-over-time B1) — byte-identical
    // to the direct ReportInventory path, independently guarded + isolated.
    if (app_perf_daily_store_ && app_perf_daily_store_->is_open()) {
        try {
            ingest_app_perf_report(*app_perf_daily_store_, agent_id, *request, *response, metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("[gateway] ProxyInventory: app_perf ingest threw for agent={} — acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("[gateway] ProxyInventory: app_perf ingest threw (unknown) for agent={} "
                         "— acked",
                         agent_id);
        }
    }
    // Typed device_ci via its shared seam (ADR-0016) — byte-identical to the direct
    // ReportInventory path, independently guarded + isolated.
    if (device_inventory_store_ && device_inventory_store_->is_open()) {
        try {
            ingest_device_ci_report(*device_inventory_store_, agent_id, *request, *response,
                                    metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("[gateway] ProxyInventory: device_ci ingest threw for agent={} — acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("[gateway] ProxyInventory: device_ci ingest threw (unknown) for agent={} "
                         "— acked",
                         agent_id);
        }
    }
    // Typed software_licensing via its shared seam (ADR-0024 Decision 5) —
    // byte-identical to the direct ReportInventory path, independently guarded
    // + isolated.
    if (software_licensing_store_ && software_licensing_store_->is_open()) {
        try {
            ingest_software_licensing_report(*software_licensing_store_, agent_id, *request,
                                             *response, metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("[gateway] ProxyInventory: software_licensing ingest threw for agent={} "
                         "— acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("[gateway] ProxyInventory: software_licensing ingest threw (unknown) for "
                         "agent={} — acked",
                         agent_id);
        }
    }
    response->set_received(true);
    return grpc::Status::OK;
}

// -- NotifyStreamStatus -------------------------------------------------------

grpc::Status
GatewayUpstreamServiceImpl::NotifyStreamStatus(grpc::ServerContext* context,
                                               const gw::StreamStatusNotification* request,
                                               gw::StreamStatusAck* response) {
    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    const auto& agent_id = request->agent_id();
    const auto& session_id = request->session_id();

    // Verify session
    {
        std::lock_guard lock(sessions_mu_);
        auto it = gateway_sessions_.find(session_id);
        if (it == gateway_sessions_.end() || it->second != agent_id) {
            spdlog::warn("[gateway] NotifyStreamStatus: unknown session {} for agent {}",
                         session_id, agent_id);
            // 4.2a #8: this in-memory gateway_sessions_ guard, not the
            // directory store, but the same "systemic desync visibility"
            // signal the architect flagged as the dominant post-restart
            // symptom (a replica that lost its gateway_sessions_ map, or a
            // notification for a session that was never wired through
            // ProxyRegister on this replica).
            record_directory_desync(metrics_, "notify_stream_status", "unknown_session");
            response->set_acknowledged(false);
            return grpc::Status::OK;
        }
    }

    switch (request->event()) {
    case gw::StreamStatusNotification::CONNECTED: {
        // PLAN item 5 (CC-03, peer finding PLAN-007): `wire_capabilities` was
        // read off the wire and dropped on the floor here — p3's advertised
        // capability set never reached the registry, so the dispatch
        // chokepoint's routed-path gateway-capability check (agent_registry.cpp)
        // had nothing to consult and every gateway session looked
        // capability-less. Record the FULL set exactly as advertised; a
        // reconnect (a fresh CONNECTED, which this branch always is —
        // `wire_capabilities` is sent with EVERY CONNECTED notification, not
        // only the first) REPLACES it, never merges.
        //
        // M1 (review finding, post-merge round): node + capabilities publish
        // through ONE call, `set_gateway_route` — they used to be two calls,
        // which both raced `send_to`/`send_to_all`'s reads on `gateway_node`
        // (a C++ data race: written under a different lock than it was read
        // under) and exposed an observable intermediate state (node set,
        // capabilities not yet replaced) that could false-deny a dispatch.
        std::vector<std::string> wire_capabilities(request->wire_capabilities().begin(),
                                                    request->wire_capabilities().end());
        registry_.set_gateway_route(agent_id, request->gateway_node(),
                                    std::move(wire_capabilities));
        // HA WS-4 4.1: mirror the same CONNECTED fact into the durable,
        // cross-replica routing directory (gateway_route_store.hpp) — INERT
        // this slice, nothing reads it for dispatch yet. Fail-open: a
        // degraded write here does NOT fail this notification or touch
        // registry_.set_gateway_route above.
        if (gateway_route_store_) {
            // 4.2a #8: a session recorded in lost_race_sessions_ lost its
            // register_fresh epoch race — the durable row already belongs to
            // a NEWER connection, so calling announce_connected here would
            // only report matched=false and pollute the desync counter with
            // an expected, benign race loss (see record_directory_desync's
            // header comment). Skip the directory write entirely; registry_
            // .set_gateway_route above is unaffected (legacy in-memory
            // routing is not gated on the epoch race).
            bool skip_announce = false;
            {
                std::lock_guard lock(sessions_mu_);
                skip_announce = lost_race_sessions_.contains(session_id);
            }
            if (skip_announce) {
                spdlog::debug("[gateway] NotifyStreamStatus CONNECTED: session {} lost its "
                             "register_fresh epoch race — skipping directory announce_connected",
                             session_id);
            } else if (auto res = gateway_route_store_->announce_connected(
                           agent_id, session_id, request->cluster_id(), request->gateway_node(),
                           kGatewayRouteLeaseTtlSecs);
                       !res) {
                record_route_store_failure(metrics_, "announce_connected", res.error());
            } else if (!res->matched) {
                record_directory_desync(metrics_, "announce_connected", "session_mismatch");
            }
        }
        spdlog::info("[gateway] Agent {} stream CONNECTED at gateway node '{}' ({} wire "
                     "capabilit{})",
                     agent_id, request->gateway_node(), request->wire_capabilities_size(),
                     request->wire_capabilities_size() == 1 ? "y" : "ies");
        break;
    }

    case gw::StreamStatusNotification::DISCONNECTED:
        // `clear_stream_if_session` also clears the advertised-capability set
        // (agent_registry.cpp) — a session whose stream is gone has nothing
        // live to route a dispatch-tagged command through, so no separate
        // clear call is needed here.
        registry_.clear_stream_if_session(agent_id, session_id);
        registry_.remove_agent_if_session(agent_id, session_id);
        // HA WS-4 4.1: mirror the DISCONNECTED fact into the durable routing
        // directory too — session-guarded (gateway_route_store.hpp), so a
        // stale/superseded session's DISCONNECTED can't tear down a newer
        // re-home. Fail-open: a degraded write here does not affect the
        // registry cleanup above.
        if (gateway_route_store_) {
            if (auto res = gateway_route_store_->deregister(agent_id, session_id); !res) {
                record_route_store_failure(metrics_, "deregister", res.error());
            } else if (!res->removed) {
                record_directory_desync(metrics_, "deregister", "session_mismatch");
            }
        }
        {
            std::lock_guard lock(sessions_mu_);
            gateway_sessions_.erase(session_id);
            lost_race_sessions_.erase(session_id);
        }
        spdlog::info("[gateway] Agent {} stream DISCONNECTED at gateway node '{}'", agent_id,
                     request->gateway_node());
        break;

    default:
        spdlog::warn("[gateway] NotifyStreamStatus: unknown event {} for agent {}",
                     static_cast<int>(request->event()), agent_id);
        response->set_acknowledged(false);
        return grpc::Status::OK;
    }

    response->set_acknowledged(true);
    return grpc::Status::OK;
}

// -- ForwardGuardianMessage ---------------------------------------------------

grpc::Status
GatewayUpstreamServiceImpl::ForwardGuardianMessage(grpc::ServerContext* context,
                                                   const gw::ForwardGuardianRequest* request,
                                                   gw::ForwardGuardianAck* response) {
    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    const auto& agent_id = request->agent_id();

    // agent_id is gateway-asserted (the gateway stamps the agent's bound
    // Subscribe-stream identity, not a value from the frame). Do a cheap
    // diagnostic lookup, but LOG-AND-ACCEPT on a miss rather than reject: the
    // registry's gateway view is populated by best-effort NotifyStreamStatus
    // (dropped while the upstream circuit is open), so a strict "must be
    // registered" gate would silently lose real drift events during exactly
    // the reconnect storms Guardian most needs to report. Accept matches the
    // best-effort durability posture (durable buffering is Guardian A3). Debug
    // level so the happy path (agent always registered via ProxyRegister) does
    // not spam logs at fleet scale.
    if (!registry_.get_session(agent_id)) {
        spdlog::debug("[gateway] ForwardGuardianMessage: agent {} not in registry "
                      "(accepting anyway — best-effort)",
                      agent_id);
    }

    const auto& resp = request->response();
    if (resp.plugin() != "__guard__" || !resp.command_id().empty()) {
        // Defence-in-depth: the gateway only forwards UNSOLICITED "__guard__" events
        // (no command_id) here; a mislabelled frame, or a SOLICITED reply that should
        // have gone through normal command correlation (command_id set — H2 / #1209),
        // must not be ingested as a Guardian event. Drop it (still ack — we consumed
        // the RPC). A solicited reply reaching this path is a gateway routing bug.
        spdlog::warn("[gateway] ForwardGuardianMessage: not an unsolicited guardian event "
                     "(plugin='{}', command_id='{}') from agent {} — dropping",
                     resp.plugin(), resp.command_id(), agent_id);
        response->set_acknowledged(true);
        return grpc::Status::OK;
    }

    if (guaranteed_state_store_) {
        // Shared one-true-path ingest (same fn the direct Subscribe loop uses).
        ingest_guardian_response(*guaranteed_state_store_, agent_id, resp,
                                 blast_radius_detector_, dex_alert_router_, metrics_);
    } else {
        spdlog::warn("[gateway] ForwardGuardianMessage: no guaranteed-state store wired — "
                     "dropping event from agent {}",
                     agent_id);
    }

    response->set_acknowledged(true);
    return grpc::Status::OK;
}

// -- session_count ------------------------------------------------------------

std::size_t GatewayUpstreamServiceImpl::session_count() const {
    std::lock_guard lock(sessions_mu_);
    return gateway_sessions_.size();
}

} // namespace yuzu::server::detail
