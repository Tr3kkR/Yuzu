#pragma once

namespace yuzu::server {

/// Where an agent client-cert issuance request entered the server. Threaded into
/// the single `sign_agent_csr` chokepoint (shared by the direct Register and the
/// gateway-proxied ProxyRegister paths) so the `ca.cert.issued` audit row records
/// HOW the cert was minted.
///
/// Why it matters (#1290 / PKI PR5 R-5 residual): a compromised gateway can
/// CSR-swap to forge a leaf for any `agent_id`. That confused-deputy risk is
/// accepted for M1 with the compensating control "every forged leaf is recorded in
/// ca_issued + revocable" — but without a `via` discriminator an incident
/// responder cannot tell which issued certs came through a (potentially
/// compromised) gateway, i.e. the exact population to scope when bulk-revoking
/// after a gateway compromise. SOC 2 CC7.2 lineage.
enum class CertIssuanceSource {
    Direct,       ///< AgentServiceImpl::Register — agent connected directly.
    GatewayProxy, ///< GatewayUpstreamServiceImpl::ProxyRegister — relayed by the gateway.
};

/// Stable token for the `via=` field of a `ca.cert.issued` / `ca.cert.reissue_blocked`
/// audit detail. Kept short + greppable for SIEM lineage queries; do NOT rename
/// without updating the audit consumers.
constexpr const char* to_audit_via(CertIssuanceSource src) {
    return src == CertIssuanceSource::GatewayProxy ? "gateway_proxy" : "direct";
}

} // namespace yuzu::server
