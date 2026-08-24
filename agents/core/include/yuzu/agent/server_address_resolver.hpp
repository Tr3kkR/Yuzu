#pragma once

/**
 * server_address_resolver.hpp -- resolves the agent's configured server
 * target ("host:port", possibly a hostname) to concrete IP literal(s) ONCE
 * at agent startup, before any plugin (including quarantine) ever runs.
 *
 * WHY THIS LIVES HERE, RESOLVED AT STARTUP, AND CACHED -- not re-resolved
 * on demand by a plugin at the moment it's needed: quarantine's whitelist
 * derivation used to call getaddrinfo() directly, at quarantine-DISPATCH
 * time, on the host BEING quarantined -- letting that host's own live
 * resolver state (a poisoned /etc/hosts, a compromised local resolver, a
 * hostile DHCP-served nameserver) decide which address survives its own
 * containment. Quarantine is normally dispatched IN RESPONSE to a
 * suspected compromise, so resolving at that exact moment is close to the
 * worst possible timing for trusting the local resolver. Resolving once
 * here, at boot, narrows the window to "compromised before or at agent
 * startup" instead. It also means quarantine-time performs NO DNS I/O at
 * all: resolve_server_address_literals() below is bounded, so a wedged
 * resolver delays agent startup once rather than blocking every future
 * quarantine/unquarantine/whitelist dispatch (which all share one
 * mutation gate in the quarantine plugin).
 *
 * Threaded into every plugin's config as "agent.server_address_resolved"
 * by Agent::Run() (agent.cpp), read by the quarantine plugin's
 * do_quarantine instead of resolving anything itself.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <string>
#include <string_view>

namespace yuzu::agent {

/// Returns a comma-joined list of IP literal(s) that `target`'s host
/// portion resolves to. `target` is a gRPC-style "host:port" string (the
/// agent's own --server config) -- an already-IP-literal host is returned
/// as-is (no DNS round-trip); a hostname is resolved via a BOUNDED
/// getaddrinfo() call on a background task, discarded on timeout. Empty on
/// failure, timeout, or an unparseable target -- never blocks the caller
/// past the bound.
YUZU_EXPORT std::string resolve_server_address_literals(std::string_view target);

} // namespace yuzu::agent
