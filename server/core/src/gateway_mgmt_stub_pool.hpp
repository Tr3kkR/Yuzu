#pragma once

#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "agent.grpc.pb.h" // yuzu::agent::v1::CommandResponse (classify_gateway_forward_response)
#include "management.grpc.pb.h"

/// @file gateway_mgmt_stub_pool.hpp
/// HA WS-4 "rest of 4.3" — cross-cluster gateway fan-out. Three independent
/// pieces:
///
///   - `parse_gateway_cluster_addrs`: pure parser for `--gateway-cluster-addr`
///     CLI entries (`cluster_id=host:port`), called from main.cpp BEFORE
///     `Server::create()` so a malformed entry is a CLI exit, not a lenient
///     boot-time warning (this is a routing-correctness input, unlike
///     `trusted_nat_cidrs`' own lenient-parse precedent).
///   - `GatewayMgmtStubPool`: an EAGER, immutable map of
///     `ManagementService::Stub`s, one per configured gateway cluster, built
///     once at server construction (`server.cpp`, alongside the pre-4.3
///     single `gw_mgmt_stub_`/`gw_mgmt_channel_` construction it replaces).
///     `grpc::CreateChannel` is itself lazy-connecting, so eager construction
///     of every configured channel/stub costs nothing and needs no lock on
///     the dispatch hot path (`ServerImpl::forward_gateway_pending`).
///   - `classify_gateway_forward_response`: pure classification of one
///     `SendCommandResponse` read off a forwarding stream, extracted out of
///     `forward_gateway_pending`'s detached-thread lambda (quality-engineer
///     Gate 3 finding) so the agent-id mismatch guard and the `not_connected`
///     synthetic-failure detection are unit-testable without a live gRPC
///     connection — no fake `ManagementService` harness exists in this
///     codebase, and this is the cheap seam that avoids needing one for
///     these two decisions specifically.
///
/// Design per the 4.3 plan's Fable pre-implementation review:
///   - Resolution is TWO-MODE, not a uniform "empty means default, non-empty
///     unmapped means drop" rule — the latter is a BREAKING CHANGE on
///     upgrade, since every existing gateway build announces a non-empty
///     `cluster_id` (`YUZU_GW_CLUSTER_ID`, defaulting to the literal
///     `"default"` when unset — `yuzu_gw_upstream.erl`), not an empty
///     string. Single-cluster mode (no `--gateway-cluster-addr` configured)
///     therefore ignores whatever `cluster_id` a command carries entirely
///     and always resolves to the one legacy `gateway_command_address` stub
///     — byte-for-byte today's pre-4.3 behavior. Multi-cluster mode (the
///     flag IS configured) auto-aliases the key `"default"` to
///     `gateway_command_address` (if set and not already an explicit key)
///     so the gateway's implicit id is modeled, and only then does an
///     unmapped non-empty `cluster_id` become a real config defect.
///   - The resolved LABEL (for the `yuzu_server_gateway_forward_total`
///     metric's `cluster_id` label) is always the matched config key or the
///     fixed literal `"unknown"` — never the raw gateway-asserted wire
///     string, even after ingest clamping (`gateway_service_impl.cpp`'s
///     `kMaxClusterIdLen`) — an attacker-influenced value is still a
///     cardinality risk as a metric label, however bounded in length.
///
/// TRUST BOUNDARY (unhappy-path Gate 4 finding UP-7): `--gateway-cluster-addr`
/// is fully operator-trusted config, like every other CLI flag. Nothing here
/// (or in `forward_gateway_pending`) verifies that the `host:port` configured
/// for a given `cluster_id` is actually THAT cluster — mTLS via the shared
/// credentials authenticates core's OWN identity to whatever peer answers at
/// that address, it does not authenticate the peer's identity back to core
/// (that's the gateway-side #1422 mgmt-plane peer pin, a different
/// direction). A stale/wrong DNS entry or a copy-paste error in the flag
/// value silently dials the wrong cluster with no detectable signal beyond
/// whatever that peer's own behavior reveals. This is the same trust
/// assumption every other operator-authored infra config in this codebase
/// carries — named explicitly here because it's easy to misread the mTLS
/// dial as a verification it isn't.
namespace yuzu::server {

/// Parses `--gateway-cluster-addr` entries, each already a single
/// `"cluster_id=host:port"` token (CLI11's `->delimiter(',')` has already
/// split the comma list before this runs — see main.cpp). Returns an error
/// string, never exits — the caller (main.cpp) decides how loudly to fail.
/// Rejected: an entry with no `=`, an empty key or value, a key exceeding
/// `max_cluster_id_len` (pass `gateway_service_impl.hpp`'s `kMaxClusterIdLen`
/// — declared there, not duplicated, so this call site and the CONNECTED-time
/// ingest clamp in `gateway_service_impl.cpp` share the same bound), or a
/// duplicate key.
[[nodiscard]] inline std::expected<std::unordered_map<std::string, std::string>, std::string>
parse_gateway_cluster_addrs(const std::vector<std::string>& entries,
                            std::size_t max_cluster_id_len) {
    std::unordered_map<std::string, std::string> result;
    for (const auto& entry : entries) {
        auto eq = entry.find('=');
        if (eq == std::string::npos) {
            return std::unexpected("--gateway-cluster-addr entry '" + entry +
                                   "' is missing '=' (expected cluster_id=host:port)");
        }
        std::string key = entry.substr(0, eq);
        std::string value = entry.substr(eq + 1);
        if (key.empty()) {
            return std::unexpected("--gateway-cluster-addr entry '" + entry +
                                   "' has an empty cluster_id");
        }
        if (value.empty()) {
            return std::unexpected("--gateway-cluster-addr entry '" + entry +
                                   "' has an empty address for cluster_id '" + key + "'");
        }
        if (key.size() > max_cluster_id_len) {
            return std::unexpected("--gateway-cluster-addr cluster_id '" + key +
                                   "' exceeds the maximum length (" +
                                   std::to_string(max_cluster_id_len) + " bytes)");
        }
        if (!result.emplace(std::move(key), std::move(value)).second) {
            return std::unexpected("--gateway-cluster-addr has a duplicate cluster_id '" +
                                   entry.substr(0, eq) + "'");
        }
    }
    return result;
}

/// The literal both single-cluster and multi-cluster mode use for the
/// legacy/default entry — see the file header comment.
inline constexpr std::string_view kDefaultGatewayClusterKey = "default";
inline constexpr std::string_view kUnknownGatewayClusterLabel = "unknown";

class GatewayMgmtStubPool {
public:
    using Stub = ::yuzu::server::v1::ManagementService::Stub;
    using ChannelFactory =
        std::function<std::shared_ptr<grpc::Channel>(const std::string& address,
                                                       std::shared_ptr<grpc::ChannelCredentials>)>;

    static std::shared_ptr<grpc::Channel>
    default_channel_factory(const std::string& address,
                            std::shared_ptr<grpc::ChannelCredentials> creds) {
        return grpc::CreateChannel(address, std::move(creds));
    }

    /// `default_address` is `Config::gateway_command_address` (may be
    /// empty); `cluster_addresses` is the parsed `--gateway-cluster-addr`
    /// map (may be empty — that IS single-cluster mode, decided once here at
    /// construction, not re-derived per resolve() call). `credentials` is
    /// shared across every channel this pool builds — reused, never
    /// per-cluster (the mgmt-plane peer pin, #1422, lives on the gateway
    /// side per-cluster, not something core varies its own identity for).
    GatewayMgmtStubPool(std::string default_address,
                        std::unordered_map<std::string, std::string> cluster_addresses,
                        std::shared_ptr<grpc::ChannelCredentials> credentials,
                        ChannelFactory channel_factory = default_channel_factory)
        : multi_cluster_mode_(!cluster_addresses.empty()) {
        if (multi_cluster_mode_) {
            if (!default_address.empty() &&
                !cluster_addresses.contains(std::string(kDefaultGatewayClusterKey))) {
                cluster_addresses.emplace(std::string(kDefaultGatewayClusterKey),
                                          std::move(default_address));
            }
            for (auto& [id, addr] : cluster_addresses) {
                entries_.emplace(id, make_entry(addr, credentials, channel_factory));
                known_clusters_.insert(id);
            }
        } else if (!default_address.empty()) {
            entries_.emplace(std::string(kDefaultGatewayClusterKey),
                             make_entry(default_address, credentials, channel_factory));
        }
    }

    [[nodiscard]] bool empty() const { return entries_.empty(); }
    [[nodiscard]] bool multi_cluster_mode() const { return multi_cluster_mode_; }
    /// Every configured cluster_id key (multi-cluster mode only — the
    /// auto-aliased `"default"` included). For
    /// `GatewayUpstreamServiceImpl::set_known_gateway_clusters`'
    /// CONNECTED-time early-warning wiring. Empty in single-cluster mode —
    /// callers must check `multi_cluster_mode()` first, an empty set there
    /// is NOT "nothing is routable", it means "the check doesn't apply."
    [[nodiscard]] const std::unordered_set<std::string>& known_clusters() const {
        return known_clusters_;
    }

    struct Resolution {
        Stub* stub = nullptr;
        /// Resolved metric-label value — the matched config key, or
        /// `kUnknownGatewayClusterLabel`. NEVER the raw wire cluster_id.
        std::string label;
    };

    /// `cluster_id` is `GatewayPendingCmd::cluster_id` — `nullopt`/empty
    /// means "no cluster identity available" (a direct agent, or a gateway
    /// build predating 4.1/4.3). See the file header comment for the
    /// two-mode resolution rule.
    [[nodiscard]] Resolution resolve(const std::optional<std::string>& cluster_id) const {
        std::string key(kDefaultGatewayClusterKey);
        if (multi_cluster_mode_ && cluster_id && !cluster_id->empty()) {
            key = *cluster_id;
        }
        auto it = entries_.find(key);
        if (it == entries_.end()) {
            return {nullptr, multi_cluster_mode_ ? std::string(kUnknownGatewayClusterLabel) : key};
        }
        return {it->second.stub.get(), key};
    }

private:
    struct Entry {
        std::shared_ptr<grpc::Channel> channel;
        std::unique_ptr<Stub> stub;
    };

    static Entry make_entry(const std::string& address,
                            const std::shared_ptr<grpc::ChannelCredentials>& credentials,
                            const ChannelFactory& channel_factory) {
        Entry e;
        e.channel = channel_factory(address, credentials);
        e.stub = ::yuzu::server::v1::ManagementService::NewStub(e.channel);
        return e;
    }

    bool multi_cluster_mode_;
    std::unordered_map<std::string, Entry> entries_;
    std::unordered_set<std::string> known_clusters_;
};

/// Outcome of classifying one `SendCommandResponse` read from a forwarding
/// stream, against the single `agent_id` the enclosing request targeted
/// (`forward_gateway_pending` sends exactly one per request — never a
/// broadcast). `kAgentMismatch` means REFUSE: the caller must NOT apply the
/// response (`process_gateway_response`) — see `classify_gateway_forward_
/// response`'s doc comment for why. `kApply` and `kNotConnected` both mean
/// apply it; `kNotConnected` additionally means the caller should count a
/// DISTINCT metric outcome instead of the generic terminal "ok" the
/// surrounding `Finish()` check would otherwise record (a streamed error
/// response still completes the RPC with `OK`).
enum class GatewayForwardOutcome { kApply, kAgentMismatch, kNotConnected };

/// Fable pre-implementation review, finding 6a (cross-trust-zone response
/// forgery): a response naming a different `agent_id` than the one this
/// request targeted is either a gateway bug or — on a compromised gateway
/// sharing one core credential across multiple trust-zone clusters (the
/// design this slice ships) — a forged terminal status for an agent that
/// gateway never held. ADR-2002 §7's whole reason for per-cluster isolation
/// is trust-zone separation; refuse rather than apply it.
///
/// Fable pre-implementation review, finding 1a: a gateway-side "agent not
/// connected on this cluster" error (`yuzu_gw_mgmt_service.erl`'s
/// `stream_responses/3`) arrives as a FAILURE response with a real
/// `command_id` (as of the paired gateway fix) but a synthetic
/// `output`/`exit_code` — distinguish it so it isn't silently folded into
/// "ok" by the caller (a streamed error response still returns `Finish() ==
/// OK`). This is the PRIMARY signal of a stale/wrong cluster resolution in a
/// multi-cluster deployment, so it must be separately countable.
[[nodiscard]] inline GatewayForwardOutcome
classify_gateway_forward_response(const ::yuzu::server::v1::SendCommandResponse& resp,
                                  const std::string& expected_agent_id) {
    if (resp.agent_id() != expected_agent_id) {
        return GatewayForwardOutcome::kAgentMismatch;
    }
    if (resp.response().status() == ::yuzu::agent::v1::CommandResponse::FAILURE &&
        resp.response().exit_code() == -1 &&
        (resp.response().output() == "not_connected" ||
         resp.response().output() == "agent_disconnected")) {
        return GatewayForwardOutcome::kNotConnected;
    }
    return GatewayForwardOutcome::kApply;
}

} // namespace yuzu::server
