# Wave 2 handoff — WP-C (discovery plugin)

`agents/plugins/discovery/src/discovery_plugin.cpp` now has **zero surviving
spawn sites**. The five spawns it had before this package (`popen("arp -a")`
/ `popen("arp -n")` at the old :151/:153, and three `system()` ping calls at
the old :324/:328/:332) are all gone:

- Windows ARP read: `GetIpNetTable v1` → `GetIpNetTable2(AF_INET, ...)`
  (native, `FreeMibTable`'d on every exit path).
- Linux ARP read: `popen("arp -n")` → `/proc/net/arp` read + the new pure
  `yuzu::discovery::parse_proc_net_arp` (`discovery_parsers.hpp`).
- macOS ARP read: `popen("arp -a")` → `sysctl NET_RT_FLAGS/RTF_LLINFO` +
  the new pure `yuzu::shared::parse_rt_flags_llinfo`
  (`agents/shared/route_sysctl_arp.hpp`).
- Ping sweep: three platform `system()` calls → one shared
  `yuzu::shared::IcmpSession` per `scan_subnet` invocation (never per host),
  with an honest CONSTRAINED/UNAVAILABLE degrade when the socket can't be
  opened, instead of a silently-empty sweep.

Zero manifest rows for the CI spawn inventory — only this seed-inventory
line: `discovery: 0 spawn sites (was 5)`.

`WP-C` does not edit `tests/meson.build` — the integrator wires the two new
test TUs into `agent_test_exe`.

## tests/meson.build

Append these two lines to `agent_test_exe`'s `files(...)` source list:

```
'unit/test_discovery_parsers.cpp',   # WP-C: pure /proc/net/arp parser (portable, unguarded)
'unit/test_route_sysctl_arp.cpp',    # WP-C: pure sysctl NET_RT_FLAGS/RTF_LLINFO parser (__APPLE__-guarded body)
```

`agents/shared` is already on that target's `include_directories` (win_str.hpp
entry), so `route_sysctl_arp.hpp` needs no new include path. `discovery_parsers.hpp`
lives under the plugin's own `src/`, which is **not** yet on the list — add
this new entry alongside the other pure-parser plugin-src entries:

```
include_directories('../agents/plugins/discovery/src'),  # discovery_parsers.hpp (WP-C, pure /proc/net/arp parser)
```

## Fixture provenance

- `test_discovery_parsers.cpp` embeds the two-line table section (header +
  one resolved entry, `172.17.0.1` / `8e:2a:cd:00:41:28`) of
  `~/.claude/wave2-prestage/fixtures/linux/proc_net_arp.out` as a raw string
  literal, verified byte-for-byte against the source file. The rest of that
  capture (`bash: line 5: ip: command not found`, `=== gateway: ===` /
  `=== /proc/net/arp ===` banners) is capture-harness noise, not fixture
  data, and is not embedded.
- `test_route_sysctl_arp.cpp` embeds the full 2296-byte
  `~/.claude/wave2-prestage/fixtures/macos/rt_flags_llinfo.bin` blob as a
  `constexpr unsigned char[]` hex array (captured 2026-08-14 on this host by
  `dump_rt_flags.c`; the `.meta` file records only the byte count, so the
  16 `rt_msghdr` records and their 15 resolved `{ip, mac}` entries were
  decoded independently — with a standalone verification program built
  against this same host's real `<net/route.h>`/`<net/if_dl.h>` — and the
  derived entries are recorded in a comment beside the array and asserted
  in the test).

## Boundaries respected

- Did not touch `agents/shared/icmp_probe.hpp`, `runner_status.hpp`,
  `sudo_argv.hpp`, `host_arg.hpp` (WP-0's, read-only to this package) — only
  `#include`d `icmp_probe.hpp`.
- Did not touch `agents/plugins/netprobe/**` or `agents/plugins/wol/**`.
- Did not add/rename/remove an action, change `is_valid_cidr`/`parse_cidr`/
  `enumerate_hosts`/`resolve_hostname`, the timeout_ms clamp, or any output
  row's shape.
- No netlink `RTM_GETNEIGH` implementation added — `/proc/net/arp` is the
  approved deviation; netlink stays a recorded future promotion in the
  Linux leg's descriptor `fallback` field.
- No socket-injection seam or fd-exhaustion test added for the generic
  socket-failure branch (`!session.ok() && session.permitted`) — that
  branch is proved by code shape and review only, per the spec's explicit
  test-efficiency carve-out.
