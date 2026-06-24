%%%-------------------------------------------------------------------
%%% @doc Inventory wire-contract tests (ADR-0016) — gpb must preserve the
%%% daily-sync hash-skip fields end-to-end through the gateway proxy.
%%%
%%% ReportInventory is proxied: the gateway decodes the agent's InventoryReport
%%% via agent_pb, then RE-ENCODES it upstream via gateway_pb (the ProxyInventory
%%% marshal_fun), and decodes the server's InventoryAck via gateway_pb before
%%% returning it to the agent via agent_pb. gpb SILENTLY DROPS any wire field
%%% absent from a module's vendored proto — so if `content_hashes` (request) or
%%% `need_full` (ack) weren't mirrored into the gateway's vendored agent.proto
%%% AND regenerated into BOTH agent_pb and gateway_pb, the hash-skip + cold-cache
%%% resync would break ONLY in gateway mode (direct works) — the hardest
%%% regression to catch. These exercise the exact production hops.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_inventory_wire_tests).
-include_lib("eunit/include/eunit.hrl").

%% Forward hop (agent -> server): content_hashes (map<string,string>, field 4)
%% must survive agent_pb DECODE (what the gateway receives) then gateway_pb
%% ENCODE (the ProxyInventory marshal upstream). plugin_data rides along to
%% prove the full payload also forwards.
content_hashes_survives_gateway_forward_test() ->
    Report = #{session_id     => <<"sess-1">>,
               content_hashes => #{<<"installed_software">> => <<"deadbeefhash">>},
               plugin_data    => #{<<"installed_software">> => <<"chrome-blob">>}},
    Decoded = agent_pb:decode_msg(
                agent_pb:encode_msg(Report, 'yuzu.agent.v1.InventoryReport'),
                'yuzu.agent.v1.InventoryReport'),
    Forwarded = gateway_pb:decode_msg(
                  gateway_pb:encode_msg(Decoded, 'yuzu.agent.v1.InventoryReport'),
                  'yuzu.agent.v1.InventoryReport'),
    ?assertEqual(#{<<"installed_software">> => <<"deadbeefhash">>},
                 maps:get(content_hashes, Forwarded, undefined)),
    ?assertEqual(#{<<"installed_software">> => <<"chrome-blob">>},
                 maps:get(plugin_data, Forwarded, undefined)).

%% Return hop (server -> agent): need_full (repeated string, field 2 on
%% InventoryAck) must survive gateway_pb DECODE (the do_rpc unmarshal of the
%% server's ack) then agent_pb ENCODE (what the agent receives). This is the
%% opposite direction and a different module from the forward test.
need_full_survives_gateway_return_test() ->
    Ack = #{received => true, need_full => [<<"installed_software">>]},
    AckDecoded = gateway_pb:decode_msg(
                   gateway_pb:encode_msg(Ack, 'yuzu.agent.v1.InventoryAck'),
                   'yuzu.agent.v1.InventoryAck'),
    AckOut = agent_pb:decode_msg(
               agent_pb:encode_msg(AckDecoded, 'yuzu.agent.v1.InventoryAck'),
               'yuzu.agent.v1.InventoryAck'),
    ?assertEqual([<<"installed_software">>], maps:get(need_full, AckOut, undefined)),
    ?assertEqual(true, maps:get(received, AckOut, undefined)).
