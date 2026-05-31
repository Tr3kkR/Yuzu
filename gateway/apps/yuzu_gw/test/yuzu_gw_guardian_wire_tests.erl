%%%-------------------------------------------------------------------
%%% @doc Guardian wire-contract tests — gpb must preserve the Guardian
%%% side-channel fields end-to-end through the gateway.
%%%
%%% In gateway mode the C++ server and the agent both speak the canonical
%%% proto/yuzu/agent/v1/agent.proto, but the gateway re-marshals every
%%% CommandRequest/CommandResponse through its OWN gpb-generated agent_pb.
%%% gpb's decoder SILENTLY SKIPS any wire field absent from the gateway's
%%% vendored proto — so if a Guardian field isn't mirrored into
%%% gateway/priv/proto/agent.proto, it is stripped in transit and the
%%% feature breaks ONLY in gateway mode (direct mode works), which is the
%%% hardest kind of regression to catch.
%%%
%%% These tests hand-craft the exact wire bytes a field-aware peer (the C++
%%% server) emits, then decode them through agent_pb. That isolates the
%%% DECODE path (the actual strip mechanism) and is independent of whether
%%% agent_pb's encoder knows the field.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_guardian_wire_tests).
-include_lib("eunit/include/eunit.hrl").

%% A length-delimited (wire type 2) field: tag byte then a single-byte
%% length (caller keeps payloads < 128 bytes) then the raw bytes.
-define(LEN_DELIM_TAG(FieldNum), ((FieldNum bsl 3) bor 2)).

%% Half A (server -> agent push): CommandRequest.payload = 8 carries the
%% serialized GuaranteedStatePush. Embedded NUL + a high byte prove it is
%% `bytes`, not a UTF-8 string (which is exactly why it can't ride in the
%% `parameters` string map).
command_request_payload_survives_decode_test() ->
    Payload = <<"guardian-push", 0, 255>>,
    ?assert(byte_size(Payload) < 128),
    Base = #{command_id => <<"g1">>,
             plugin     => <<"__guard__">>,
             action     => <<"push_rules">>,
             parameters => #{}},
    BaseBin = agent_pb:encode_msg(Base, 'yuzu.agent.v1.CommandRequest'),
    Wire = <<BaseBin/binary,
             ?LEN_DELIM_TAG(8), (byte_size(Payload)), Payload/binary>>,
    Decoded = agent_pb:decode_msg(Wire, 'yuzu.agent.v1.CommandRequest'),
    ?assertEqual(Payload, maps:get(payload, Decoded, undefined)).
