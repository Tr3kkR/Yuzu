#!/usr/bin/env python3
"""check-seam-closure.py - per-family INCLUDE-CLOSURE seam-enforcement gate
(ADR-0031 migration step 3, WS-A4 item 1).

ADR-0031's migration step 3 requires that a family's presentation/handler
translation units do NOT reach a data store directly - they call the
in-process API instead. This script is the first per-family scaffold for that
rule (issue tracked under the /split control plane's WS-A4 item 1); today it
covers exactly one family, `network` (see FAMILIES below).

WHAT THIS IS: a sound-for-its-stated-claim INCLUDE-CLOSURE check, NOT a full
static analysis and NOT a substitute for review. The enforceable proxy for
"this translation unit does not touch a store" is: the TRANSITIVE `#include`
closure of the TU contains no store header. To call `store->method()` the
class definition has to be VISIBLE via some include, so if no header in the
closure defines a store class, the TU cannot be calling into one directly.
That implication only breaks two ways, both ACKNOWLEDGED and NOT caught here:

  1. A COMPUTED / macro-built include (`#include SOME_MACRO`, X-macro headers,
     `#define STORE_HEADER "foo_store.hpp"` + `#include STORE_HEADER`) - the
     literal filename this script's regex extracts would not be the real
     target, or there would be no filename to extract at all.
  2. A translation unit that hand-re-declares a store class's body (or a
     subset of its member signatures) locally instead of including its real
     header - the closure walk never sees the real header because the code
     never asked for it, yet the call still resolves at link time.

Neither shape exists in the family this script covers today; if one is ever
introduced, this check will pass while the seam is actually broken. That is a
known, stated gap - not a silent one.

ABSTRACT-VS-LOCAL SEAM (#4249): the fourth forbidden pattern,
`*_api_local.hpp`, is NOT a store-layer header - it is the CORE-ONLY half of
a family's in-process API. #4249 splits `network_api.hpp` into the ABSTRACT
interface (what a presentation TU is allowed to call) and a new
`network_api_local.hpp` holding the store-backed FACTORY
(`make_local_network_api`) that wires that interface up to real stores. The
local header deliberately carries NO store `#include`s of its own - only
forward declarations - so the three store patterns above CANNOT see a
presentation TU that wrongly includes it, and the abstract/local boundary
would be convention only. Naming the local header itself is what makes the
boundary enforced rather than advisory. WHAT IT CATCHES: any enforced family
TU (route / renderer / model / the abstract API header) that reaches a
`*_api_local.hpp` anywhere in its include closure - i.e. a presentation TU
helping itself to the store-backed factory instead of receiving the abstract
interface. It is NOT a ban on the header existing or being used: `server.cpp`
(core wiring), the family's own `*_api.cpp` implementation, and the tests all
include it legitimately, and none of those is in any family's enforced TU
set. The local header ITSELF, however, IS in the family's enforced TU set:
a TU is excluded from its own include closure (closure() seeds `seen` with
the TU), so it never self-matches this pattern, and enforcing it makes its
own purity (forward declarations only, zero store `#include`s) lint-checked
rather than review-only. Being an include-closure check, this pattern
carries exactly the SAME acknowledged escape as shape 2 above, in the same
class and for the same reason: a presentation TU that hand-re-declares the
factory's signature locally instead of including the header still links,
and this script will never see it. Two further NAME-LEVEL escapes are
inherent to a basename glob and are stated here so the whole escape list
lives in one place: a core-only factory header that is not literally named
`*_api_local.hpp` (the template prescribes that name for every family), and
the `.hpp`-only / case-sensitive match (a `.h`/`.hxx` or differently-cased
spelling is not caught; the tree has neither). Known and stated, not silent.

INCLUDE RESOLUTION: this project spells project-internal, cross-component
headers `<yuzu/...>` (server/core/meson.build's own
`include_directories(['include', '../../common/include'])`), so ANGLE
BRACKETS ARE NOT A RELIABLE "this is third-party, never a store" SIGNAL here -
`server/core/include/yuzu/server/scim_store.hpp` is a real store header
reachable via `#include <yuzu/server/scim_store.hpp>`. A checker that only
followed quote-includes would treat that as an unwatched escape hatch, on top
of the two above. This script therefore follows BOTH quote and angle
includes, resolving each one against the project's actual include roots
(mirroring the compiler's own quote-then-search-path / angle-search-path
distinction - see `resolve_include()`); an angle-bracket spelling that does
not resolve inside `server/core/include` or `common/include` is treated as a
genuine external/system/vendored header (the C++ stdlib, httplib, spdlog,
libpq-fe, ...), which by construction cannot define one of this project's own
store classes, so treating it as opaque there is sound.

FAMILY COVERAGE: today this checks exactly the `network` family's dashboard
(`network_ui.cpp`), REST-route (`network_routes.cpp`), and model
(`network_perf_model.cpp`) translation units, plus the in-process API header
(`network_api.hpp`) the sibling INV-31-4 change is introducing beside them.
The network family's REST-handler TWIN registrations live inside
`rest_api_v1.cpp`, and its MCP-tool twin inside `mcp_server.cpp` - BOTH are
multi-family translation units that legitimately hold real store access for
~20 OTHER families each. An include-closure check applied to either whole
file would trivially fail (or be gamed by scoping) and would say nothing
meaningful about the network family specifically. Those two files' network
sections are therefore INSPECTED-NOT-ENFORCED - reviewed by hand today, not
gated by this script - until a block-scoped or symbol-scoped successor
exists. Do not read a clean run of this script as covering them.

USAGE
  check-seam-closure.py          # run the gate (CI mode); 0 pass / 1 fail
"""
from __future__ import annotations

import fnmatch
import re
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
SERVER_CORE = ROOT / "server" / "core"
SERVER_SRC = SERVER_CORE / "src"
SERVER_INCLUDE = SERVER_CORE / "include"
COMMON_INCLUDE = ROOT / "common" / "include"


class Roots(NamedTuple):
    """The resolution roots an include closure walk is parameterized over -
    threaded explicitly (never read off module globals mid-walk) so the
    selftest can point a walk at a synthetic tree without monkeypatching."""
    root: Path
    server_src: Path
    server_include: Path
    common_include: Path


DEFAULT_ROOTS = Roots(ROOT, SERVER_SRC, SERVER_INCLUDE, COMMON_INCLUDE)

# ── Forbidden header patterns (store layer + the core-only API half) ─────
# Evidence (see the PR description / junior report for the exact commands):
#   - `ls server/core/src/*_store.hpp` -> 43 files, every server store header
#     in the tree (device_store.hpp, quarantine_store.hpp, ... including
#     `server/core/include/yuzu/server/scim_store.hpp` by BASENAME match -
#     `*_store.hpp` matches regardless of which directory the header lives
#     under, which is what closes the angle-bracket `<yuzu/server/
#     scim_store.hpp>` escape noted in the module docstring above).
#   - `agent_registry.hpp` (server/core/src/agent_registry.hpp) is the
#     in-process agent/device registry - not named `*_store.hpp` but is the
#     same class of direct-data-access surface a presentation TU must not
#     reach past the seam.
#   - `server/core/src/pg/*.hpp` (pg_pool.hpp, pg_exec.hpp, pg_raii.hpp,
#     pg_migration_runner.hpp, pg_retention_guard.hpp, pg_array.hpp,
#     pg_session_advisory_lock.hpp, secret_codec.hpp) is the shared
#     Postgres-connection/raw-SQL layer EVERY store is built on
#     (`PgPool`, `PQexecParams`-wrapping `exec_param`/`exec_params`,
#     `PgResult`/`PgConn` RAII) - a TU that includes one of these can issue
#     raw SQL against the pool directly, bypassing any store class entirely,
#     which the `*_store.hpp` pattern alone would not catch.
#   - `*_api_local.hpp` (#4249) is the ONLY non-store pattern here: it
#     enforces the ABSTRACT-vs-LOCAL seam boundary within a family's own
#     in-process API. The local header declares the store-backed factory
#     (`make_local_network_api`) but holds only FORWARD DECLARATIONS of the
#     stores it wires, so the three patterns above are blind to it - a
#     presentation TU including it would reach the factory with a clean
#     store closure. It is legitimately included by `server.cpp` (core
#     wiring), by the family's own `*_api.cpp` implementation, and by tests
#     - none of which is in any family's enforced TU set - but NEVER by a
#     route / renderer / model TU, which is exactly what this pattern gates.
#     See the module docstring's "ABSTRACT-VS-LOCAL SEAM" section for the
#     acknowledged hand-re-declaration escape it shares with shape 2.
FORBIDDEN_HEADER_PATTERNS = [
    "*_store.hpp",
    "agent_registry.hpp",
    "pg/*.hpp",
    "*_api_local.hpp",
]

# ── Family definitions ────────────────────────────────────────────────────
# Two families so far: `network` (WS-A4 item 1's pilot) and `verify` (WS-A4
# #4250, the SECOND family through the seam). Each set covers the
# presentation-side TUs plus BOTH halves of the seam header pair: the
# abstract `*_api.hpp` and the core-only `*_api_local.hpp` (#4249). Enforcing
# the local header pins its own purity (forward decls only); it cannot
# self-match `*_api_local.hpp` because a TU is excluded from its own closure.
# A declared-but-missing TU is a hard error - see `check_family()`.
#
# `verify`'s closure was NOT clean before #4250's rewire: `verify_routes.hpp`
# used to include `dex_app_perf_model.hpp` (for the retired `AppPerfCohortFn`)
# AND `dex_routes.hpp` (for `DexRoutes::AuditFn`) - the latter transitively
# reaches `dex_app_perf_ui.hpp` -> `dex_app_perf_model.hpp` regardless, which
# itself `#include`s `app_perf_daily_store.hpp` + `app_perf_fleet_store.hpp`
# (both `*_store.hpp`). The rewire (1) replaced the cohort provider with the
# `VerifyApi` seam, (2) relocated the pure `app_perf_param_valid`/
# `kAppPerfParamCap` validator out of `dex_app_perf_model.hpp` into the
# already-pure `app_perf_compare.hpp`, and (3) defined `VerifyRoutes::AuditFn`
# LOCALLY (same shape as `DexRoutes::AuditFn`/`NetworkRoutes::AuditFn`)
# instead of borrowing `dex_routes.hpp` for one type alias - which is what
# actually makes this family's closure clean, not merely dropping one include.
FAMILIES = {
    "network": {
        "tus": [
            "server/core/src/network_routes.cpp",
            "server/core/src/network_ui.cpp",
            "server/core/src/network_perf_model.cpp",
            "server/core/src/network_api.hpp",
            "server/core/src/network_api_local.hpp",
        ],
    },
    "verify": {
        "tus": [
            "server/core/src/verify_routes.cpp",
            "server/core/src/verify_ui.cpp",
            "server/core/src/verify_api.hpp",
            "server/core/src/verify_api_local.hpp",
        ],
    },
}

_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*(<[^>]+>|"[^"]+")')


def gh(kind, msg):
    # stderr, matching check-api-parity.py's convention.
    print(f"::{kind}::{msg}", file=sys.stderr, flush=True)


def parse_includes(path: Path):
    """Yields (is_angle, spelling) for every `#include` line in `path`, in
    file order. Line-anchored regex, not a real preprocessor - a `#include`
    reached only through an `#if 0`/macro-guarded block is still extracted as
    if unconditional. That is conservative in the direction that matters for
    this gate (it can only make the walk see MORE of the tree, never hide a
    real include), so it is not a soundness gap for the "no store in the
    closure" claim, only a possible source of a false-positive edge the
    escapes section above does not need to cover."""
    out = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        m = _INCLUDE_RE.match(line)
        if not m:
            continue
        spelling = m.group(1)
        is_angle = spelling.startswith("<")
        out.append((is_angle, spelling[1:-1]))
    return out


def resolve_include(includer: Path, is_angle: bool, name: str, roots: Roots = DEFAULT_ROOTS):
    """Resolve one `#include` spelling to an absolute in-tree Path, or None if
    it is a genuine external/system/vendored header this checker cannot (and
    need not) see inside. See the module docstring's "INCLUDE RESOLUTION"
    section for why angle vs quote is not itself the external/internal
    signal in this codebase."""
    if is_angle:
        for r in (roots.server_include, roots.common_include):
            candidate = r / name
            if candidate.is_file():
                return candidate.resolve()
        return None
    # Quote form: directory of the includer first (ordinary compiler
    # behaviour), then the same internal roots plus server/core/src itself
    # (a fallback for a quote-include reaching a sibling file by a path
    # relative to src/ rather than to the includer's own subdirectory).
    for d in (includer.parent, roots.server_include, roots.common_include, roots.server_src):
        candidate = d / name
        if candidate.is_file():
            return candidate.resolve()
    return None


def closure(tu_path: Path, roots: Roots = DEFAULT_ROOTS):
    """BFS the `#include` closure of `tu_path`.

    Returns (visited, parent, unresolved):
      visited    - set of resolved absolute Paths reached (excludes tu_path
                   itself).
      parent     - {child_path: includer_path} for chain reconstruction.
      unresolved - [(includer_path, spelling)] for a QUOTE include that could
                   not be resolved anywhere in the tree. Quote includes in
                   this codebase are always in-tree by construction, so an
                   unresolved one is reported as a warning (an extraction
                   gap to fix, not itself evidence of a store reach) rather
                   than silently ignored. An unresolved ANGLE include is the
                   expected, common case (a real external header) and is not
                   reported at all.
    """
    tu_path = tu_path.resolve()
    visited: set[Path] = set()
    parent: dict[Path, Path] = {}
    unresolved: list[tuple[Path, str]] = []
    seen = {tu_path}
    queue = [tu_path]
    while queue:
        cur = queue.pop(0)
        for is_angle, name in parse_includes(cur):
            resolved = resolve_include(cur, is_angle, name, roots)
            if resolved is None:
                if not is_angle:
                    unresolved.append((cur, name))
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            visited.add(resolved)
            parent[resolved] = cur
            queue.append(resolved)
    return visited, parent, unresolved


def chain_to(target: Path, parent: dict[Path, Path], tu_path: Path):
    """Reconstructs the include chain from `tu_path` to `target` (inclusive
    of both ends) by walking `parent` backward."""
    chain = [target]
    cur = target
    while cur in parent:
        cur = parent[cur]
        chain.append(cur)
    chain.reverse()
    return chain


def is_forbidden_header(abspath: Path, root: Path = ROOT,
                         patterns=FORBIDDEN_HEADER_PATTERNS):
    """Returns (True, matched_pattern) if `abspath` matches any forbidden
    pattern (store-layer, or the core-only `*_api_local.hpp` seam half) -
    checked against BOTH the bare basename (so
    `*_store.hpp` fires regardless of which directory the header lives
    under, closing the angle-bracket `<yuzu/server/scim_store.hpp>` escape)
    and the root-relative path (so a directory-qualified pattern like
    `pg/*.hpp` only fires on a real `pg/` subdirectory, not on a file that
    merely happens to end the right way)."""
    rel = str(abspath.relative_to(root)).replace("\\", "/")
    base = abspath.name
    for pat in patterns:
        if fnmatch.fnmatch(base, pat):
            return True, pat
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, "*/" + pat):
            return True, pat
    return False, None


def check_family(name: str, tus: list[str], roots: Roots = DEFAULT_ROOTS,
                  patterns=FORBIDDEN_HEADER_PATTERNS) -> bool:
    """Runs the seam-closure check for one family. `tus` is a list of
    root-relative path strings; a declared member that does not exist on
    disk is a HARD ERROR (never silently skipped - a missing family member
    is exactly the kind of "the check quietly covers less than it claims"
    defect this gate exists to prevent), reported and then EXCLUDED from the
    closure walk so the remaining members are still checked."""
    ok = True
    existing: list[Path] = []
    for rel in tus:
        p = (roots.root / rel).resolve()
        if not p.is_file():
            gh("error", f"check-seam-closure: expected family TU not found: "
                        f"{rel} (family {name!r})")
            ok = False
            continue
        existing.append(p)

    for tu in existing:
        rel_tu = tu.relative_to(roots.root)
        visited, parent, unresolved = closure(tu, roots)
        for includer, spelling in unresolved:
            gh("warning",
               f"check-seam-closure: {rel_tu}: could not resolve quote-"
               f"include \"{spelling}\" from "
               f"{includer.relative_to(roots.root)} (extraction gap, not "
               f"itself a store-header finding)")
        for f in sorted(visited, key=str):
            hit, pat = is_forbidden_header(f, roots.root, patterns)
            if not hit:
                continue
            chain = chain_to(f, parent, tu)
            chain_str = " -> ".join(str(c.relative_to(roots.root)) for c in chain)
            gh("error",
               f"check-seam-closure: family {name!r}: {rel_tu} reaches "
               f"forbidden header {f.relative_to(roots.root)} (matches "
               f"forbidden pattern {pat!r}) via include chain: {chain_str}")
            ok = False
    return ok


def run_check() -> int:
    ok = True
    checked = 0
    for name, spec in FAMILIES.items():
        checked += 1
        if not check_family(name, spec["tus"]):
            ok = False
    if ok:
        print(f"check-seam-closure: OK ({checked} famil"
              f"{'y' if checked == 1 else 'ies'} checked, all closures free "
              f"of store-layer and core-only `*_api_local.hpp` headers)")
    return 0 if ok else 1


def main() -> int:
    return run_check()


if __name__ == "__main__":
    sys.exit(main())
