#include "command_outbox_delivery.hpp"

#include "audit_store.hpp"
#include "command_outbox_store.hpp"
#include "execution_tracker.hpp"
#include "leader_elector.hpp" // kServerBackgroundLeaderLock, LeaderElector::epoch()

#include <yuzu/metrics.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <exception>

namespace yuzu::server {

namespace {

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Decode the opaque producer-serialized payload the outbox round-trips: a JSON
// array of agent ids and a JSON object of scalar parameters (exactly what
// ScheduleRunner stores — `s.parameter_values` is already canonical JSON, and
// agent id lists are dumped as a JSON array). Returns false on malformed JSON so
// the caller fails the occurrence closed rather than dispatching with a
// silently-empty target/param set.
bool decode_payload(const OutboxCommand& c, std::vector<std::string>& agent_ids,
                    std::unordered_map<std::string, std::string>& params) {
    try {
        if (!c.agent_ids.empty()) {
            auto arr = nlohmann::json::parse(c.agent_ids);
            if (!arr.is_array())
                return false;
            for (const auto& e : arr) {
                if (!e.is_string())
                    return false;
                agent_ids.push_back(e.get<std::string>());
            }
        }
        if (!c.parameters.empty()) {
            auto obj = nlohmann::json::parse(c.parameters);
            if (!obj.is_object())
                return false;
            for (auto it = obj.begin(); it != obj.end(); ++it) {
                params[it.key()] = it.value().is_string() ? it.value().get<std::string>()
                                                          : it.value().dump();
            }
        }
    } catch (const nlohmann::json::exception&) {
        return false;
    }
    return true;
}

} // namespace

CommandOutboxDelivery::CommandOutboxDelivery(Deps deps) : d_(std::move(deps)) {}

void CommandOutboxDelivery::tick() {
    if (!d_.outbox || !d_.leader || !d_.dispatch_fn || !d_.resolve_caller)
        return;
    // Read the fenced epoch ONCE per tick. `nullopt` means this replica does not
    // currently hold leadership — the FencedLeaderOnly gate should have stopped
    // us, so this is a defensive bail (never dispatch, never mark) rather than a
    // reason to guess an epoch.
    const auto epoch = d_.leader->epoch();
    if (!epoch)
        return;
    const std::string lock = kServerBackgroundLeaderLock;

    auto pending = d_.outbox->list_pending(d_.max_per_tick);
    if (!pending) {
        // Typed degraded read (authoritative store) — never treated as "nothing
        // owed"; log + count and retry next tick.
        count("yuzu_server_command_outbox_deliver_degraded_total");
        spdlog::warn("command_outbox_delivery: list_pending degraded — deferring this tick");
        return;
    }
    for (const auto& c : *pending) {
        if (d_.should_stop && d_.should_stop()) {
            spdlog::info("command_outbox_delivery: tick stopping early on shutdown — "
                         "remaining occurrence(s) deferred");
            break;
        }
        try {
            deliver(c, lock, *epoch);
        } catch (const std::exception& e) {
            // A per-occurrence failure must not starve the rest. Treat an
            // unexpected throw as transient and reschedule (back-off) so the
            // occurrence is retried, not silently dropped — the stable
            // command_id keeps the eventual redelivery effectively-once.
            count("yuzu_server_command_outbox_deliver_errors_total");
            spdlog::error("command_outbox_delivery: deliver threw for occurrence '{}': {}",
                          c.occurrence_id, e.what());
            (void)d_.outbox->reschedule(c.occurrence_id, lock, *epoch, d_.retry_backoff);
        }
    }
}

void CommandOutboxDelivery::deliver(const OutboxCommand& c, const std::string& lock_name,
                                    std::int64_t epoch) {
    // 1. Re-authorize at SEND time — authority may have been revoked since
    //    enqueue. Fail-closed on an unset check. A denial is PERMANENT.
    if (!d_.arming_check || !d_.arming_check(c.principal, c.plugin, c.action)) {
        count("yuzu_server_command_outbox_deliver_denied_total");
        spdlog::warn("command_outbox_delivery: occurrence '{}' arming denied at delivery — "
                     "principal='{}' target={}.{}",
                     c.occurrence_id, c.principal, c.plugin, c.action);
        (void)d_.outbox->mark_failed(c.occurrence_id, lock_name, epoch, "authority_denied");
        if (d_.execution_tracker && !c.execution_id.empty())
            (void)d_.execution_tracker->mark_cancelled(c.execution_id, c.principal);
        audit(c, "denied", "authority_denied_at_delivery");
        return;
    }

    // 2. Decode the opaque payload. A malformed row is a permanent failure —
    //    fail closed rather than dispatch with an empty target/param set.
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> params;
    if (!decode_payload(c, agent_ids, params)) {
        count("yuzu_server_command_outbox_deliver_decode_failed_total");
        spdlog::error("command_outbox_delivery: occurrence '{}' payload decode failed — "
                      "marking failed",
                      c.occurrence_id);
        (void)d_.outbox->mark_failed(c.occurrence_id, lock_name, epoch, "payload_decode_failed");
        if (d_.execution_tracker && !c.execution_id.empty())
            (void)d_.execution_tracker->mark_cancelled(c.execution_id, c.principal);
        audit(c, "failure", "payload_decode_failed");
        return;
    }

    // 3. Re-resolve the caller from the stored principal (never a serialized
    //    DispatchCaller — #1398) and stamp the approval provenance the
    //    occurrence carries. THIS is the declared #1398 stamping site for
    //    outbox dispatch (dispatch_caller.hpp closed list).
    auto caller = d_.resolve_caller(c.principal);
    caller.approval_provenance =
        c.approval_id.empty() ? ApprovalProvenance::None : ApprovalProvenance::Ticket;

    // 4. Dispatch through the PLAIN confined path with the STABLE command_id
    //    (R1: no ADR-1007 concurrency claim — a re-drive of an already-delivered
    //    device is absorbed by the agent's command_id dedup).
    const auto outcome = d_.dispatch_fn(c.plugin, c.action, agent_ids, c.scope_expr, params,
                                        c.execution_id, caller, c.command_id);

    // 5. A systemic transient gate failure (a degraded containment read) is NOT
    //    a delivered occurrence — retry with back-off, leave it pending.
    if (outcome.containment_unreadable) {
        count("yuzu_server_command_outbox_deliver_retry_total");
        spdlog::warn("command_outbox_delivery: occurrence '{}' containment unreadable — "
                     "rescheduling",
                     c.occurrence_id);
        (void)d_.outbox->reschedule(c.occurrence_id, lock_name, epoch, d_.retry_backoff);
        return;
    }

    // 6. Finalize the (fire-time-created) execution row so it cannot idle to the
    //    materialise timeout (executions ladder). sent>0 → targeted count;
    //    sent==0 (no agents in scope right now) → cancel, matching
    //    ScheduleRunner's historical no-agents handling.
    if (d_.execution_tracker && !c.execution_id.empty()) {
        if (outcome.sent > 0) {
            if (!d_.execution_tracker->set_agents_targeted(c.execution_id, outcome.sent))
                (void)d_.execution_tracker->mark_cancelled(c.execution_id, c.principal);
        } else {
            (void)d_.execution_tracker->mark_cancelled(c.execution_id, c.principal);
        }
    }

    // 7. Terminal (fire-and-advance): mark sent so the occurrence is not
    //    re-driven. A missed occurrence (sent==0) is recorded and skipped, never
    //    spun into a backlog. mark_sent==false (fenced out / already terminal) is
    //    harmless — the row then stays pending for the true leader, whose send
    //    the agent dedups.
    (void)d_.outbox->mark_sent(c.occurrence_id, lock_name, epoch);
    count("yuzu_server_command_outbox_delivered_total");
    spdlog::info("command_outbox_delivery: delivered occurrence '{}' — command_id={} "
                 "execution_id={} agents={}",
                 c.occurrence_id, c.command_id, c.execution_id, outcome.sent);
    audit(c, outcome.sent > 0 ? "success" : "failure",
          "sent=" + std::to_string(outcome.sent) + " command_id=" + c.command_id +
              " execution_id=" + c.execution_id);
}

void CommandOutboxDelivery::audit(const OutboxCommand& c, const std::string& result,
                                  const std::string& detail) {
    if (!d_.audit_store)
        return;
    AuditEvent ev;
    ev.timestamp = now_epoch_seconds();
    ev.principal = c.principal;
    ev.action = "command.outbox_delivered";
    ev.target_type = "command";
    ev.target_id = c.command_id.empty() ? c.occurrence_id : c.command_id;
    ev.result = result;
    ev.detail = "source=" + c.source + " occurrence_id=" + c.occurrence_id + " plugin=" +
                c.plugin + " action=" + c.action + " " + detail;
    (void)d_.audit_store->log(ev);
}

void CommandOutboxDelivery::count(const char* name) {
    if (d_.metrics)
        d_.metrics->counter(name).increment();
}

} // namespace yuzu::server
