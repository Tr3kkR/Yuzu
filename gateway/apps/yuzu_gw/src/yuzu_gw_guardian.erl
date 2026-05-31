%%%-------------------------------------------------------------------
%%% @doc Gateway-side interception of the Guardian "__guard__" side-channel.
%%%
%%% Guardian drift events travel agent -> server as UNSOLICITED
%%% CommandResponses (plugin="__guard__", action="event", payload = a
%%% serialized GuaranteedStateEvent) — they carry no command_id and are not a
%%% reply to any dispatched command. In gateway mode the agent's Subscribe
%%% stream terminates at the gateway, so such a frame would fall through to the
%%% "Orphaned response" drop in yuzu_gw_agent:streaming/3. This module is the
%%% single decision point that recognises those frames and forwards them
%%% upstream via GatewayUpstream.ForwardGuardianMessage instead.
%%%
%%% Kept deliberately thin and separate from yuzu_gw_agent (small-module
%%% preference): classification + delegation only. The bounded, circuit-aware
%%% RPC send lives in yuzu_gw_upstream where the breaker and channel already
%%% live, so this module adds no new failure-handling surface.
%%%
%%% SECURITY: AgentId is the gateway-asserted identity passed in by the caller
%%% (the agent's bound gen_statem state), NEVER read from the frame — a
%%% compromised/buggy agent therefore cannot attribute a drift event to another
%%% agent. See docs/yuzu-guardian-design-v1.1.md §24.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_guardian).

-export([intercept/2, is_guardian_frame/1]).

%% Reserved plugin name for the Guardian side-channel (mirrors the C++
%% server's "__guard__" intercept in agent_service_impl.cpp and the agent's
%% reserved-name handling in agent.cpp).
-define(GUARD_PLUGIN, <<"__guard__">>).

%% @doc If ResponseFrame is a Guardian side-channel message, forward it
%% upstream and return `forwarded`; otherwise return `passthrough` so the
%% caller runs its normal command-correlation handling. Forwarding is
%% fire-and-forget (a cast into yuzu_gw_upstream) so this never blocks the
%% caller's gen_statem.
-spec intercept(binary(), map()) -> forwarded | passthrough.
intercept(AgentId, ResponseFrame) ->
    case is_guardian_frame(ResponseFrame) of
        true ->
            yuzu_gw_upstream:forward_guardian_message(AgentId, ResponseFrame),
            forwarded;
        false ->
            passthrough
    end.

%% @doc A frame is a Guardian side-channel message iff its `plugin` field is
%% the reserved "__guard__" name. Reads the binary key first then the atom key,
%% mirroring how yuzu_gw_agent reads command_id/plugin (gpb maps decode yields
%% atom keys; the binary-key fallback keeps it robust to either shape).
-spec is_guardian_frame(term()) -> boolean().
is_guardian_frame(Frame) when is_map(Frame) ->
    ?GUARD_PLUGIN =:= maps:get(<<"plugin">>, Frame,
                               maps:get(plugin, Frame, undefined));
is_guardian_frame(_) ->
    false.
