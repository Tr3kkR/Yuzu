#include "quarantine_containment_reconciler.hpp"

#include "agent_registry.hpp"
#include "audit_store.hpp"
#include "quarantine_reapply.hpp"
#include "quarantine_store.hpp"
#include "response_store.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <chrono>

namespace yuzu::server {

namespace {
std::int64_t default_now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::chrono::milliseconds next_backoff(std::chrono::milliseconds cur, std::chrono::milliseconds cap) {
    const auto doubled = cur * 2;
    return doubled > cap ? cap : doubled;
}

// Concatenates every returned response row's `output` in oldest-first order
// (the store returns newest-first) so a multi-frame status response (the
// plugin's `do_status` can emit a `state|` line followed by a separate
// `whitelist|` line) reads as one payload for
// `parse_quarantine_endpoint_state`.
std::string combined_output(const std::vector<StoredResponse>& rows) {
    std::string out;
    for (auto it = rows.rbegin(); it != rows.rend(); ++it) {
        if (!out.empty())
            out += '\n';
        out += it->output;
    }
    return out;
}
} // namespace

QuarantineContainmentReconciler::QuarantineContainmentReconciler(Deps deps) : d_(std::move(deps)) {}

std::int64_t QuarantineContainmentReconciler::now_epoch() const {
    return d_.now_fn ? d_.now_fn() : default_now_epoch();
}

std::chrono::milliseconds QuarantineContainmentReconciler::min_reapply_interval() const {
    return d_.min_reapply_interval_override.count() > 0 ? d_.min_reapply_interval_override
                                                        : kMinReapplyInterval;
}

std::chrono::milliseconds QuarantineContainmentReconciler::response_wait() const {
    return d_.response_wait_override.count() > 0 ? d_.response_wait_override : kResponseWait;
}

std::chrono::milliseconds QuarantineContainmentReconciler::verify_grace() const {
    return d_.verify_grace_override.count() > 0 ? d_.verify_grace_override : kVerifyGrace;
}

void QuarantineContainmentReconciler::count(const char* result) const {
    if (d_.metrics)
        d_.metrics->counter("yuzu_server_quarantine_reapply_total", {{"result", result}})
            .increment();
}

void QuarantineContainmentReconciler::audit_reapply(const std::string& agent_id,
                                                     const std::string& command_id,
                                                     std::string_view trigger) const {
    if (!d_.audit_store || !d_.audit_store->is_open())
        return;
    AuditEvent ev;
    ev.timestamp = default_now_epoch();
    ev.principal = "system";
    ev.action = "quarantine.reapply";
    ev.target_type = "Security";
    ev.target_id = agent_id;
    ev.detail = "command_id=" + command_id + " trigger=" + std::string(trigger);
    ev.result = "success";
    (void)d_.audit_store->log(ev);
}

void QuarantineContainmentReconciler::audit_confirmed(const std::string& agent_id,
                                                       const std::string& command_id) const {
    if (!d_.audit_store || !d_.audit_store->is_open())
        return;
    AuditEvent ev;
    ev.timestamp = default_now_epoch();
    ev.principal = "system";
    ev.action = "quarantine.reapply";
    ev.target_type = "Security";
    ev.target_id = agent_id;
    ev.detail = "CONFIRMED command_id=" + command_id;
    ev.result = "success";
    (void)d_.audit_store->log(ev);
}

void QuarantineContainmentReconciler::tick() {
    if (!d_.quarantine_store) {
        count("degraded");
        return;
    }
    auto rows = d_.quarantine_store->list_quarantined();
    if (!rows) {
        // Fail closed: a degraded read is NEVER treated as "nothing active"
        // — that would silently stop reconciling every currently-contained
        // device for as long as the read stays degraded.
        count("degraded");
        return;
    }

    std::unordered_set<std::string> active_ids;
    active_ids.reserve(rows->size());
    for (const auto& r : *rows)
        active_ids.insert(r.agent_id);

    std::vector<std::string> to_reconcile;
    double unconfirmed_connected = 0;
    double unconfirmed_offline = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = state_.begin(); it != state_.end();) {
            if (!active_ids.contains(it->first))
                it = state_.erase(it); // released since the last tick
            else
                ++it;
        }
        for (const auto& agent_id : active_ids) {
            auto& st = state_[agent_id]; // default-constructs an unconfirmed entry
            if (st.confirmed) {
                // Session churn (#3425 review): a reconnect after a reboot
                // wipes the endpoint's firewall rules even though the
                // record never changed — a stale "confirmed" would be a
                // false assurance. Verify via `status` first, not a blind
                // re-apply, so a still-genuinely-contained reconnect
                // doesn't needlessly contend with the agent-side mutation
                // gate for no reason.
                auto sess = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
                if (sess && sess->session_id != st.confirmed_session_id) {
                    st.confirmed = false;
                    st.verify_first = true;
                }
            }
            if (!st.confirmed) {
                to_reconcile.push_back(agent_id);
                auto sess = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
                if (sess)
                    unconfirmed_connected += 1;
                else
                    unconfirmed_offline += 1;
            }
        }
        unconfirmed_cache_ =
            std::unordered_set<std::string>(to_reconcile.begin(), to_reconcile.end());
    }

    // Per-replica view — never sum() this series across server instances,
    // each replica only sees the sessions its own gRPC listener holds.
    if (d_.metrics) {
        d_.metrics
            ->gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
            .set(unconfirmed_connected);
        d_.metrics
            ->gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "offline"}})
            .set(unconfirmed_offline);
    }

    std::size_t dispatched = 0;
    for (const auto& agent_id : to_reconcile) {
        if (dispatched >= kMaxDispatchesPerTick) {
            spdlog::warn("QuarantineContainmentReconciler: tick hit kMaxDispatchesPerTick ({}) — "
                        "{} unconfirmed record(s) deferred to the next tick",
                        kMaxDispatchesPerTick, to_reconcile.size() - dispatched);
            break;
        }
        reconcile_one(agent_id, "tick");
        ++dispatched;
    }
}

void QuarantineContainmentReconciler::notify_agent_heartbeat(std::string_view agent_id_sv) {
    const std::string agent_id(agent_id_sv);
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!unconfirmed_cache_.contains(agent_id))
            return; // fast path: no active unconfirmed record — no store read
    }
    reconcile_one(agent_id, "heartbeat");
}

void QuarantineContainmentReconciler::reconcile_one(const std::string& agent_id,
                                                     std::string_view trigger) {
    if (!d_.quarantine_store || !d_.dispatch_fn)
        return;

    // Claim-then-act (Guardian heartbeat reconcile precedent, server.cpp):
    // the rate-limit slot is claimed UNDER THE LOCK before any I/O, so a
    // tick and a heartbeat racing for the same agent cannot both dispatch —
    // the second caller sees the already-claimed `next_eligible_at` and
    // bails immediately. This is the concrete mechanism behind "a busy gate
    // does not spin".
    Pending pending_at_entry = Pending::none;
    std::string pending_command_id;
    std::chrono::steady_clock::time_point pending_since{};
    bool verify_first = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto& st = state_[agent_id];
        const auto now_steady = std::chrono::steady_clock::now();
        if (now_steady < st.next_eligible_at) {
            count("rate_limited");
            return;
        }
        if (st.backoff.count() == 0)
            st.backoff = min_reapply_interval(); // first-ever claim for this agent
        st.next_eligible_at = now_steady + st.backoff;
        pending_at_entry = st.pending;
        pending_command_id = st.pending_command_id;
        pending_since = st.pending_since;
        verify_first = st.verify_first;
    }

    // ── An in-flight command: poll for its response, dispatch nothing new ──
    if (pending_at_entry != Pending::none) {
        std::optional<std::vector<StoredResponse>> resp;
        if (d_.response_store)
            resp = d_.response_store->query(pending_command_id, ResponseQuery{.agent_id = agent_id});
        if (!resp) {
            count("degraded");
            return;
        }
        const auto steady_now = std::chrono::steady_clock::now();
        const bool timed_out = (steady_now - pending_since) >= response_wait();
        if (resp->empty()) {
            if (!timed_out) {
                count("pending"); // no re-dispatch — the no-spin contract
                return;
            }
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st.pending = Pending::none;
            st.verify_first = false;
            st.backoff = next_backoff(st.backoff, kMaxBackoff);
            count("not_reached");
            return;
        }

        const auto parsed = parse_quarantine_endpoint_state(combined_output(*resp));
        if (pending_at_entry == Pending::apply) {
            std::lock_guard<std::mutex> lk(mu_);
            auto& st = state_[agent_id];
            st.pending = Pending::none;
            if (parsed == QuarantineEndpointState::busy) {
                // #3429's mutation gate blocked the apply — not a failure,
                // just "already busy being quarantined". Wait for the
                // normal claim interval before trying again.
                count("busy");
                return;
            }
            // Dispatch acceptance (agents_reached>0, already known when this
            // command was issued) is not proof of containment — verify soon,
            // overriding the big claim-time interval so the follow-up isn't
            // delayed a full backoff cycle.
            st.verify_first = true;
            st.next_eligible_at = steady_now + verify_grace();
            return;
        }

        // pending_at_entry == Pending::status
        std::lock_guard<std::mutex> lk(mu_);
        auto& st = state_[agent_id];
        st.pending = Pending::none;
        if (endpoint_state_confirms_containment(parsed)) {
            (void)d_.quarantine_store->mark_endpoint_confirmed(agent_id, now_epoch());
            auto sess = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
            st.confirmed = true;
            st.confirmed_session_id = sess ? sess->session_id : std::string{};
            st.backoff = min_reapply_interval();
            audit_confirmed(agent_id, pending_command_id);
            count("confirmed");
            return;
        }
        st.backoff = next_backoff(st.backoff, kMaxBackoff);
        count(parsed == QuarantineEndpointState::busy ? "busy" : "unconfirmed");
        return;
    }

    // ── No in-flight command: reachability first, no store I/O if offline ──
    auto session = d_.registry ? d_.registry->get_session(agent_id) : nullptr;
    if (!session) {
        count("offline");
        return;
    }

    if (verify_first) {
        // Session churn on a previously-confirmed agent: confirm the record
        // is still active before dispatching (no whitelist to validate on a
        // read-only status action, so this doesn't go through
        // redispatch_stored_containment).
        auto status_res = d_.quarantine_store->get_status(agent_id);
        if (!status_res) {
            count("degraded");
            return;
        }
        if (!status_res->has_value()) {
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id); // released since verify_first was set
            return;
        }
        std::string command_id;
        int agents_reached = 0;
        bool threw = false;
        try {
            std::tie(command_id, agents_reached) =
                d_.dispatch_fn(std::string(kQuarantinePluginName), std::string(kQuarantineStatusAction),
                              {agent_id}, /*scope_expr=*/"", /*parameters=*/{}, /*execution_id=*/"");
        } catch (const std::exception&) {
            threw = true;
        }
        if (threw) {
            count("dispatch_error");
            return;
        }
        if (agents_reached == 0) {
            count("not_reached");
            return;
        }
        std::lock_guard<std::mutex> lk(mu_);
        auto& st = state_[agent_id];
        st.pending = Pending::status;
        st.pending_command_id = command_id;
        st.pending_since = std::chrono::steady_clock::now();
        st.verify_first = false;
        count("reapplied");
        return;
    }

    // Normal path: re-drive the STORED whitelist via the one shared recipe
    // (quarantine_reapply.hpp) — the same chokepoint MCP's already_active
    // retry path uses, so the stored-whitelist-only invariant lives in
    // exactly one function.
    QuarantineRecord stored{};
    auto reapply_res = redispatch_stored_containment(
        *d_.quarantine_store, agent_id,
        [&](const std::unordered_map<std::string, std::string>& params) {
            return d_.dispatch_fn(std::string(kQuarantinePluginName),
                                  std::string(kQuarantineApplyAction), {agent_id},
                                  /*scope_expr=*/"", params, /*execution_id=*/"");
        },
        stored);
    if (!reapply_res) {
        switch (reapply_res.error().kind) {
        case ContainmentReapplyErrorKind::store_error:
            count("degraded");
            break;
        case ContainmentReapplyErrorKind::no_active_record: {
            std::lock_guard<std::mutex> lk(mu_);
            state_.erase(agent_id); // released between the tick snapshot and this call
            break;
        }
        case ContainmentReapplyErrorKind::whitelist_invalid:
            count("validation_failed");
            break;
        }
        return;
    }
    if (reapply_res->dispatch_threw) {
        count("dispatch_error");
        return;
    }
    if (reapply_res->agents_reached == 0) {
        count("not_reached");
        return;
    }
    (void)d_.quarantine_store->mark_endpoint_applied(agent_id, now_epoch());
    audit_reapply(agent_id, reapply_res->command_id, trigger);
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto& st = state_[agent_id];
        st.pending = Pending::apply;
        st.pending_command_id = reapply_res->command_id;
        st.pending_since = std::chrono::steady_clock::now();
    }
    count("reapplied");
}

} // namespace yuzu::server
