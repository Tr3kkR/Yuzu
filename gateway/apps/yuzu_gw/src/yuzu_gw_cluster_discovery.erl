%%%-------------------------------------------------------------------
%%% @doc Gateway multi-node cluster FORMATION (HA WS-4 `#4555`, ADR-2002 §7b).
%%%
%%% Owns exactly one thing: whether a mesh of gateway nodes forms and STAYS
%%% formed. It does not know or care about peer health, load, or latency —
%%% that is slice 4.4's `yuzu_gw_cluster` adjacency-table gen_server, layered
%%% on top of the mesh this module maintains.
%%%
%%% ALWAYS-ON, not boot-time-only: `{connect_all, false}` is set in both
%%% `config/sys.config` and `config/sys.config.prod` (deliberately, to avoid
%%% transitive auto-mesh gossip), which means `global`/OTP never self-heals a
%%% partially-connected node set. A node that reaches only some of its
%%% resolvable peers on any given attempt (a peer's epmd up but its own node
%%% not yet registered, a transient DNS timeout, a `net_ticktime` disconnect)
%%% would stay permanently partially-meshed with nothing to ever redial it if
%%% this loop only ran once. So this gen_server ticks on a FIXED interval,
%%% FOREVER, no backoff: each tick resolves the current peer set, subtracts
%%% already-connected nodes (a `net_kernel:connect_node/1` against an
%%% already-connected peer is a harmless no-op, so the steady-state per-tick
%%% cost is one DNS query plus N cheap no-ops), and dials the remainder.
%%%
%%% Fail-open by design: a node that resolves zero peers keeps running
%%% standalone and keeps retrying — this module never refuses to let the
%%% gateway serve the agents already connected to it.
%%%
%%% Redial interval vs. `net_ticktime`: `net_ticktime` (30s, ~120s full
%%% failure-detection window per OTP's own doc — see `config/vm.args.src`'s
%%% comment) governs how long Erlang waits before declaring a node actually
%%% DOWN after a connectivity loss. The default redial interval (5s) is
%%% deliberately much SHORTER than that window: during the window, a redial
%%% attempt against a technically-still-alive-per-Erlang connection is just
%%% another harmless no-op; once `net_ticktime` finally fires `nodedown`, the
%%% NEXT tick (within one interval) reconnects — so this loop heals a real
%%% disconnect promptly without ever fighting the tick-time mechanism.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_cluster_discovery).
-behaviour(gen_server).

-export([start_link/0]).
%% exported for testing
-export([resolve_targets/0, targets_from_addrs/1, sanitize_addrs/1,
         own_short_name/0, own_short_name/1, do_tick/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_INTERVAL_MS, 5000).

%% Cap on resolved/configured peer addresses processed per tick (BLOCKING
%% fix, PR review — FortitudeEtc/Kimi+Codex, empirically reproduced:
%% 10,000 distinct addresses -> +10,000 permanent atoms, no reclaim, OTP
%% 28.4.2). `targets_from_addrs/1` atomizes one address per entry, and
%% Erlang atoms are NEVER garbage-collected — a hostile or misconfigured
%% seed-name DNS answer that rotates through fresh, syntactically-VALID
%% A-records on every 5s tick (this module's own threat model already
%% treats hostile DNS as adversarial, see `?MIN_COOKIE_LENGTH` in
%% `yuzu_gw_app.erl`) would otherwise permanently grow the VM-global atom
%% table (default cap ~1,048,576) until the whole gateway aborts, dropping
%% every connected agent, recurring on every restart while DNS stays
%% hostile. 64 is generously above any realistic cluster size
%% (`docs/erlang-gateway-blueprint.md` sizes ~1M AGENTS per gateway NODE,
%% so a cluster of dozens of nodes is already a large deployment).
-define(MAX_TARGET_ADDRS, 64).

-record(state, {interval :: pos_integer()}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    %% Clamped to a 1s floor (PR review finding): an unvalidated
    %% `YUZU_GW_CLUSTER_REDIAL_INTERVAL_MS=0` would hot-loop DNS lookups
    %% every tick, and a negative value would raise `badarg` in
    %% `erlang:send_after/3`.
    RawInterval = application:get_env(yuzu_gw, cluster_redial_interval_ms, ?DEFAULT_INTERVAL_MS),
    Interval = max(RawInterval, 1000),
    %% Non-distributed VM (a plain unit-test run, or a hand-run `rebar3 shell`
    %% without `-name`) has no distribution to form a mesh over — idle rather
    %% than crash `net_kernel:monitor_nodes/1` with `{error, not_alive}`.
    case node() of
        'nonode@nohost' ->
            ok;
        _ ->
            ok = net_kernel:monitor_nodes(true),
            self() ! tick
    end,
    {ok, #state{interval = Interval}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(tick, #state{interval = Interval} = State) ->
    do_tick(),
    erlang:send_after(Interval, self(), tick),
    {noreply, State};

handle_info({nodeup, Node}, State) ->
    telemetry:execute([yuzu, gw, cluster, node_up], #{}, #{node => node_label(Node)}),
    {noreply, State};

handle_info({nodedown, Node}, State) ->
    telemetry:execute([yuzu, gw, cluster, node_down], #{}, #{node => node_label(Node)}),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal
%%%===================================================================

do_tick() ->
    do_tick(resolve_targets()).

%% @doc The tick body, parameterised on the target list — exported for
%% testing so the connect/telemetry mechanism can be verified against a
%% real peer's REAL node name directly, without going through
%% resolve_targets/0's "peers share my own short name" address
%% construction (which cannot be exercised by two real nodes sharing one
%% EPMD/test host — see yuzu_gw_cluster_formation_multinode_tests.erl's
%% module doc for why).
-spec do_tick([node()]) -> ok.
do_tick(Targets) ->
    Connected = [node() | nodes()],
    ToDial = Targets -- Connected,
    FailedTargets = lists:foldl(fun(Target, Acc) ->
        case net_kernel:connect_node(Target) of
            true -> Acc;
            _    -> [Target | Acc]
        end
    end, [], ToDial),
    %% Self is a RESOLVED-but-never-DIALED address: DNS naturally returns
    %% every replica's address, including this node's own (a scaled Compose
    %% service resolves to all N members). `nodes()` never includes self by
    %% Erlang definition, so counting self into `peers_resolved` makes it
    %% permanently 1 higher than `peers_connected` on a fully healthy
    %% cluster — the `YuzuGatewayClusterPartiallyFormed` alert (`peers_resolved
    %% - peers_connected > 0`) would never clear. Exclude self so both gauges
    %% count EXTERNAL peers on the same basis (found + empirically verified,
    %% HA WS-4 #4555 governance Gate 4 happy-path review).
    ExternalTargets = Targets -- [node()],
    %% SCOPED to ExternalTargets, not a bare length(nodes()) (PR review
    %% finding): an unrelated inbound distributed connection (a stale node
    %% still holding the cluster cookie, a dev-shell someone left connected)
    %% would otherwise inflate `peers_connected` and could mask a genuinely
    %% failed seed peer — the YuzuGatewayClusterPartiallyFormed alert
    %% (`resolved - connected > 0`) staying clear when it shouldn't.
    ConnectedTargets = [T || T <- ExternalTargets, lists:member(T, nodes())],
    telemetry:execute([yuzu, gw, cluster, peers_resolved], #{count => length(ExternalTargets)}, #{}),
    telemetry:execute([yuzu, gw, cluster, peers_connected], #{count => length(ConnectedTargets)}, #{}),
    case FailedTargets of
        [] ->
            ok;
        _ ->
            %% Bounded, state-triggered logging (only on an actual failure,
            %% never per successful/no-op tick) — telemetry alone left an
            %% on-call operator with a bare failure COUNT and no peer names
            %% to act on before Prometheus/Grafana is wired up (consistency-
            %% auditor C-1 / sre Gate 6 finding, #4555 governance run).
            logger:warning(
                "Cluster discovery: failed to connect to ~p peer(s): ~p. "
                "Check the distribution cookie matches on every node, and "
                "that the peer's distribution port (9100-9105) and epmd "
                "(4369) are reachable.",
                [length(FailedTargets), FailedTargets]),
            telemetry:execute([yuzu, gw, cluster, connect_failed],
                               #{count => length(FailedTargets)}, #{})
    end.

%% @doc The current peer node set — an explicit static override
%% (`cluster_seed_nodes`), when non-empty, REPLACES DNS resolution outright
%% (never merged with it, per ADR-2002 §7b: two independently-configured
%% sources must never silently interact). Otherwise resolves the seed DNS
%% name's A records. Self is NOT excluded here (the caller subtracts
%% `[node() | nodes()]`) — this function answers "who is out there", not
%% "who do I still need to dial". Exported for testing.
-spec resolve_targets() -> [node()].
resolve_targets() ->
    RawAddrs = case application:get_env(yuzu_gw, cluster_seed_nodes, []) of
        [] -> resolve_seed_dns_addrs();
        Addrs -> [addr_to_string(A) || A <- Addrs]
    end,
    targets_from_addrs(sanitize_addrs(RawAddrs)).

%% @private A `cluster_seed_nodes` entry is a binary via the
%% `YUZU_GW_SEED_NODES` env-override path, but a hand-edited `sys.config`
%% written in ordinary Erlang string style (`["10.0.0.1"]`) is equally
%% valid config syntax — accept both rather than crashing this gen_server
%% every tick on the string form (PR review finding).
addr_to_string(A) when is_binary(A) -> binary_to_list(A);
addr_to_string(A) when is_list(A)   -> A.

%% @private A records for the configured seed name, as dotted-decimal
%% strings. `inet_res:lookup/3` returns `[]` on any resolution failure
%% (unset/misconfigured name, no records, timeout) — never raises — which is
%% exactly the fail-open "nothing found, try again next tick" semantics this
%% module needs.
resolve_seed_dns_addrs() ->
    SeedName = application:get_env(yuzu_gw, cluster_seed_dns_name, <<"gateway">>),
    try [inet:ntoa(Addr) || Addr <- inet_res:lookup(binary_to_list(SeedName), in, a)]
    catch Class:Reason ->
        logger:debug("Cluster discovery: DNS lookup for seed name ~p failed: ~p:~p",
                     [SeedName, Class, Reason]),
        []
    end.

%% @doc Pure: every gateway node shares the SAME short name — nodes are
%% interchangeable and distinguished only by address (ADR-2002 §7b) — so a
%% dialed node atom is always `<my own short name>@<peer address>`, never a
%% hardcoded literal duplicated between this module and `vm.args.src`.
%% Callers MUST route candidate addresses through `sanitize_addrs/1` first
%% (`resolve_targets/0` does) — this function itself does not re-validate,
%% so it stays a simple, directly-testable map. Exported for testing.
-spec targets_from_addrs([string()]) -> [node()].
targets_from_addrs(AddrStrs) ->
    Short = own_short_name(),
    [list_to_atom(Short ++ "@" ++ AddrStr) || AddrStr <- AddrStrs].

%% @doc Pure: the SINGLE chokepoint both the DNS and static-override paths
%% in `resolve_targets/0` funnel through before any address becomes an
%% atom (BLOCKING PR review fix — see `?MAX_TARGET_ADDRS`'s comment for the
%% atom-table-exhaustion threat this closes). Validates each entry is a
%% well-formed IPv4 literal (rejects a garbage/typo'd static-override entry
%% too, not just a hostile DNS answer), dedupes, and caps the count.
%% Exported for testing.
-spec sanitize_addrs([string()]) -> [string()].
sanitize_addrs(AddrStrs) ->
    Valid = lists:filter(fun is_valid_ipv4_literal/1, AddrStrs),
    Deduped = lists:usort(Valid),
    case length(Deduped) > ?MAX_TARGET_ADDRS of
        true ->
            logger:warning(
                "Cluster discovery: ~p resolved/configured addresses exceeds "
                "the ~p-address cap — truncating. Check the seed DNS name "
                "isn't returning an unexpectedly large or hostile answer.",
                [length(Deduped), ?MAX_TARGET_ADDRS]),
            lists:sublist(Deduped, ?MAX_TARGET_ADDRS);
        false ->
            Deduped
    end.

-spec is_valid_ipv4_literal(string()) -> boolean().
is_valid_ipv4_literal(AddrStr) ->
    case inet:parse_ipv4_address(AddrStr) of
        {ok, _}    -> true;
        {error, _} -> false
    end.

%% @doc This node's own short-name portion (before `@`). Exported for testing.
-spec own_short_name() -> string().
own_short_name() -> own_short_name(node()).

-spec own_short_name(node()) -> string().
own_short_name(Node) ->
    case string:split(atom_to_list(Node), "@") of
        [Short, _Host] -> Short;
        _              -> atom_to_list(Node)
    end.

node_label(Node) ->
    list_to_binary(atom_to_list(Node)).
