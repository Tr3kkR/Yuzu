/// @file device_lens_routes.cpp
/// Route registration for the DEX + Guardian device-page lenses. Split
/// verbatim out of device_routes.cpp (ADR-0031 WS-A4 wave 2) — see
/// device_lens_routes.hpp's file banner for why this stays outside the
/// `device` family's seam-closure enforcement.

#include "device_lens_routes.hpp"

#include "dex_routes.hpp"             // dex_device_score
#include "dex_view_types.hpp"         // dex_iso_since
#include "guaranteed_state_store.hpp" // dex_device_signal_summary, agent_rule_statuses, list_rules
#include "http_route_sink.hpp"
#include "rest_audit.hpp" // detail::emit_behavioral_audit (Sec-Audit-Failed, #1647)

#include <unordered_map>

namespace yuzu::server {

void DeviceLensRoutes::register_routes(httplib::Server& svr, ScopedPermFn scoped_perm_fn,
                                       const GuaranteedStateStore* store, AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(scoped_perm_fn), store, std::move(audit_fn));
}

void DeviceLensRoutes::register_routes(HttpRouteSink& sink, ScopedPermFn scoped_perm_fn,
                                       const GuaranteedStateStore* store, AuditFn audit_fn) {
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    store_ = store;
    audit_fn_ = std::move(audit_fn);

    // -- DEX lens: per-device score + signal summary (+ link to the full drill) --
    sink.Get("/fragments/device/dex", [this](const httplib::Request& req, httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // bare=1: mounted as a lens inside the Hardware CI record, which already
        // renders its own 7-tab bar — suppress this fragment's own 3-chip bar.
        const bool tabs = !req.has_param("bare");
        // Per-device behavioral data (PII): GuaranteedState:Read SCOPED to this
        // device (tier + management group) + audit-on-open. Stronger than the
        // sibling /fragments/dex/device's bare Read gate — closes the cross-scope
        // read of another team's per-device DEX summary.
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        if (!store_) {
            res.set_content(render_device_lens_placeholder("dex", id, "DEX store unavailable.", tabs),
                            "text/html; charset=utf-8");
            return;
        }
        // Behavioural-PII access audit. HTML dashboard fragment → set-and-proceed:
        // a dropped evidence row flags via Sec-Audit-Failed but STILL renders, so
        // a transient audit hiccup never blanks the operator's lens (#1647). The
        // shared helper captures the persist bool behind a try/catch (the throw
        // arm is otherwise silent) — one pattern across every behavioural route.
        (void)detail::emit_behavioral_audit(audit_fn_, req, res, "dex.device.view", "success",
                                            "Agent", id,
                                            "device DEX lens (per-device signal summary)");
        const std::string since = dex_iso_since(7);
        const int score = dex_device_score(store_, id, since);
        std::vector<std::pair<std::string, std::int64_t>> sigs;
        for (const auto& s : store_->dex_device_signal_summary(id, since))
            sigs.emplace_back(s.obs_type, s.count);
        res.set_content(render_device_dex_lens(id, score, sigs, tabs), "text/html; charset=utf-8");
    });

    // -- Guardian lens: per-guard compliance state for this device --
    sink.Get("/fragments/device/guardian", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // bare=1: mounted as a lens inside the Hardware CI record — see the dex
        // fragment above for the same suppression.
        const bool tabs = !req.has_param("bare");
        // Per-device compliance state: GuaranteedState:Read SCOPED to this device
        // (tier + management group) + audit-on-open (parity with the DEX lens above).
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        if (!store_) {
            res.set_content(render_device_lens_placeholder("guardian", id, "Guardian store unavailable.",
                                                            tabs),
                            "text/html; charset=utf-8");
            return;
        }
        // Behavioural-PII access audit — set-and-proceed (HTML fragment), parity
        // with the DEX lens above and the shared #1647 helper.
        (void)detail::emit_behavioral_audit(audit_fn_, req, res, "guardian.device.view", "success",
                                            "Agent", id,
                                            "device Guardian lens (per-guard compliance)");
        // list_rules / agent_rule_statuses are now type-distinguishable (ADR-0038
        // catastrophic-read set): a degraded read must render the same "store
        // unavailable" placeholder as the `!store_` guard above, never a silent
        // empty/partial guard list (which would misreport a device as having no
        // guards, or drop live drift verdicts, for the operator viewing this lens).
        auto rules_result = store_->list_rules();
        auto statuses_result = store_->agent_rule_statuses();
        if (!rules_result || !statuses_result) {
            res.set_content(render_device_lens_placeholder("guardian", id, "Guardian store degraded.",
                                                            tabs),
                            "text/html; charset=utf-8");
            return;
        }
        std::unordered_map<std::string, std::string> rule_names;
        for (const auto& r : *rules_result)
            rule_names[r.rule_id] = r.name;
        std::vector<DeviceGuardRow> guards;
        for (const auto& st : *statuses_result) { // all; filter to this agent
            if (st.agent_id != id)
                continue;
            DeviceGuardRow g;
            auto it = rule_names.find(st.rule_id);
            g.name = (it != rule_names.end() && !it->second.empty()) ? it->second : st.rule_id;
            g.state = st.state;
            g.updated_at = st.updated_at;
            guards.push_back(std::move(g));
        }
        res.set_content(render_device_guardian_lens(id, guards, tabs), "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
