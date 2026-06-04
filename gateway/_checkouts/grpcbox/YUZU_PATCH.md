# Vendored grpcbox (Yuzu patch — PKI PR5c)

This is a **vendored copy of grpcbox v0.17.1** (`github.com/tsloughter/grpcbox`,
the tag the gateway pins in `rebar.config` / `rebar.lock`), carried in `_checkouts/`
so rebar3 uses it in place of the fetched dependency. Only the **source** is
vendored (`src/`, `include/`, `rebar.config`, `LICENSE`); grpcbox's own deps
(chatterbox, ctx, acceptor_pool, gproc) are still fetched normally.

## The patch — one place, two lines

`src/grpcbox_pool.erl`, in `init/1` (search `YUZU PATCH`):

```erlang
%% before (stock v0.17.1):
{fail_if_no_peer_cert, true},
{verify, verify_peer},
%% after:
{fail_if_no_peer_cert, maps:get(fail_if_no_peer_cert, TransportOpts, true)},
{verify, maps:get(verify, TransportOpts, verify_peer)},
```

Stock grpcbox **hardcodes** `fail_if_no_peer_cert=true` + `verify=verify_peer` on
every TLS listener — i.e. every TLS listener is mutual TLS, with no
request-but-don't-require mode. That makes it impossible for an **unenrolled**
agent (which has no client cert until it completes CSR enrollment) to bootstrap
over a TLS gateway listener, forcing the agent↔gateway hop to stay plaintext.

The patch makes those two options read from the listener's `transport_opts` map,
**defaulting to the stock strict values** (so existing mTLS listeners are
unchanged). A listener can now opt into **one-way / server-authenticated TLS**:

```erlang
transport_opts => #{ssl => true, certfile => ..., keyfile => ..., cacertfile => ...,
                    verify => verify_none, fail_if_no_peer_cert => false}
```

which encrypts the hop + authenticates the gateway to the agent **without
requiring a client cert** — closing the plaintext agent↔gateway edge (a fleet-RCE
risk on an exposed gateway) while keeping bootstrap working. See
`docs/pki-architecture.md` "Gateway TLS".

## Integrity gate (machine-verifiable)

The exact change is committed as a canonical patch file,
`gateway/_checkouts/grpcbox.yuzu.patch`. **`gateway/scripts/verify-vendored-grpcbox.sh`**
re-clones upstream grpcbox at the `rebar.config`-pinned tag, applies that patch, and
diffs **every** vendored file against it — failing on any tamper, drift, or version
skew (so the only permitted difference between this vendor and pristine upstream is
the documented patch). It runs in CI (the `release.yml` gateway job, before compile)
and should be run on any re-sync:

```
bash gateway/scripts/verify-vendored-grpcbox.sh
```

## Re-syncing with upstream

This is intentionally a *minimal* vendor of a *pinned* tag. To move to a newer
grpcbox: re-copy `src/`+`include/`+`rebar.config`+`LICENSE` from the new tag,
re-apply `grpcbox.yuzu.patch` (or the two-line `YUZU PATCH` in
`grpcbox_pool.erl:init/1` by hand), regenerate `grpcbox.yuzu.patch` against the new
stock, bump the `{tag, "vX.Y.Z"}` pin in `rebar.config` (grpcbox stays OUT of
`rebar.lock` — it is a checkout; rebar3 refuses to lock it), update `EXPECTED_SHA`
in `gateway/scripts/verify-vendored-grpcbox.sh` to the new tag's commit, run the
gateway suite + dialyzer, and re-run `verify-vendored-grpcbox.sh`. The upstreaming target is making
`verify`/`fail_if_no_peer_cert` configurable in grpcbox itself (then this vendor can
be dropped). Tracked with PR5c.
