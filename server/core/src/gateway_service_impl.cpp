#include "gateway_service_impl.hpp"

#include <chrono>

#include <nlohmann/json.hpp>

#include "analytics_event_store.hpp"
#include "audit_store.hpp"
#include "enrollment_token_rejection.hpp"
#include "fleet_topology_store.hpp"
#include "grpc_audit_signal.hpp"
#include "guaranteed_state_store.hpp"
#include "guardian_ingest.hpp"
#include "heartbeat_ingestion.hpp"
#include "inventory_store.hpp"
#include "management_group_store.hpp"
#include "peer_ip.hpp"

namespace yuzu::server::detail {

// -- Constructor --------------------------------------------------------------

GatewayUpstreamServiceImpl::GatewayUpstreamServiceImpl(AgentRegistry& registry, EventBus& bus,
                                                       auth::AuthManager& auth_mgr,
                                                       auth::AutoApproveEngine& auto_approve,
                                                       yuzu::MetricsRegistry* metrics,
                                                       AgentHealthStore* health_store)
    : registry_(registry), bus_(bus), auth_mgr_(auth_mgr), auto_approve_(auto_approve),
      metrics_(metrics), health_store_(health_store) {}

// -- ProxyRegister ------------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::ProxyRegister(grpc::ServerContext* context,
                                                       const pb::RegisterRequest* request,
                                                       pb::RegisterResponse* response) {
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
                if (analytics_store_) {
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
                    analytics_store_->emit(std::move(ae));
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

                if (analytics_store_) {
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
                    analytics_store_->emit(std::move(ae));
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
                if (analytics_store_) {
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
                    analytics_store_->emit(std::move(ae));
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

    registry_.register_agent(info);
    // Auto-add to root management group
    if (mgmt_group_store_ && mgmt_group_store_->is_open())
        mgmt_group_store_->add_member(ManagementGroupStore::kRootGroupId, info.agent_id());

    auto session_id =
        "gw-session-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
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
            issued = agent_cert_signer_(request->csr_pem(), info.agent_id());
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
    }

    spdlog::info("[gateway] ProxyRegister succeeded: agent={}, session={}", info.agent_id(),
                 session_id);
    return grpc::Status::OK;
}

// -- BatchHeartbeat -----------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::BatchHeartbeat(grpc::ServerContext* /*context*/,
                                                        const gw::BatchHeartbeatRequest* request,
                                                        gw::BatchHeartbeatResponse* response) {
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

    response->set_acknowledged_count(acked);
    spdlog::debug("[gateway] BatchHeartbeat from node '{}': {}/{} acked", request->gateway_node(),
                  acked, request->heartbeats_size());
    return grpc::Status::OK;
}

// -- ProxyInventory -----------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::ProxyInventory(grpc::ServerContext* /*context*/,
                                                        const pb::InventoryReport* request,
                                                        pb::InventoryAck* response) {
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

    // Persist inventory data via InventoryStore (Issue 7.17)
    if (inventory_store_ && inventory_store_->is_open()) {
        int64_t collected_epoch = 0;
        if (request->has_collected_at()) {
            collected_epoch = request->collected_at().millis_epoch() / 1000;
        }
        for (const auto& [plugin_name, data_bytes] : request->plugin_data()) {
            std::string json_str(data_bytes.begin(), data_bytes.end());
            inventory_store_->upsert(agent_id, plugin_name, json_str, collected_epoch);
        }
        spdlog::info("[gateway] ProxyInventory persisted for agent={}, plugins={}", agent_id,
                     request->plugin_data_size());
    } else {
        spdlog::info("[gateway] ProxyInventory received for agent={}, plugins={} "
                     "(inventory store not available)",
                     agent_id, request->plugin_data_size());
    }
    response->set_received(true);
    return grpc::Status::OK;
}

// -- NotifyStreamStatus -------------------------------------------------------

grpc::Status
GatewayUpstreamServiceImpl::NotifyStreamStatus(grpc::ServerContext* /*context*/,
                                               const gw::StreamStatusNotification* request,
                                               gw::StreamStatusAck* response) {
    const auto& agent_id = request->agent_id();
    const auto& session_id = request->session_id();

    // Verify session
    {
        std::lock_guard lock(sessions_mu_);
        auto it = gateway_sessions_.find(session_id);
        if (it == gateway_sessions_.end() || it->second != agent_id) {
            spdlog::warn("[gateway] NotifyStreamStatus: unknown session {} for agent {}",
                         session_id, agent_id);
            response->set_acknowledged(false);
            return grpc::Status::OK;
        }
    }

    switch (request->event()) {
    case gw::StreamStatusNotification::CONNECTED:
        registry_.set_gateway_node(agent_id, request->gateway_node());
        spdlog::info("[gateway] Agent {} stream CONNECTED at gateway node '{}'", agent_id,
                     request->gateway_node());
        break;

    case gw::StreamStatusNotification::DISCONNECTED:
        registry_.clear_stream_if_session(agent_id, session_id);
        registry_.remove_agent_if_session(agent_id, session_id);
        {
            std::lock_guard lock(sessions_mu_);
            gateway_sessions_.erase(session_id);
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
GatewayUpstreamServiceImpl::ForwardGuardianMessage(grpc::ServerContext* /*context*/,
                                                   const gw::ForwardGuardianRequest* request,
                                                   gw::ForwardGuardianAck* response) {
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
                                 blast_radius_detector_);
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
