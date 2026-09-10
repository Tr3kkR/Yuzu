#!/usr/bin/env python3
"""check-mcp-retry-hints.py — lexical tripwire for the A5 "honest retry_after_ms"
standard (docs/agentic-first-principle.md / ADR-1005 exec-plan Decision 16,
routed-concerns.md's A5 row: "every new/materially-changed MCP tool ships...
honest retry_after_ms").

SCOPE: NEW OR MATERIALLY-CHANGED TOOLS ONLY, not a repo-wide retrofit. This
mirrors A5's own wording. A blanket scan of every store/query-fault error
branch across mcp_server.cpp + every REST route file produces >100 hits, the
overwhelming majority of which are existence checks, business-rule 409s, and
input-parse failures that are correctly non-retryable -- distinguishing those
from a genuine transient store/query fault is a semantic question a lexical
regex cannot answer at repo scope without an unmaintainable hand-curated
allowlist. Scoping to the tools a CHANGE actually adds or touches keeps the
diff small enough that a human reviewer (governance / colleague review) can
verify each flagged branch by hand, which is the same reason F1
(check-api-parity.py) is a RATCHET on a measured baseline rather than a
type-aware analysis of the whole tree.

WHAT THIS CATCHES, within a new/changed tool's own handler block: a variable
assigned from a function CALL (`auto x = some_call(...);`) then guarded by
`if (!x) { ... }` with an error_response()/a4_error() call inside and no
retry_after_ms. That shape is how this codebase's own review history (see the
#4030/#4036 "review finding (blocking)" comments, and
governance.d/*-mcp-retry-hardening*.jsonl) already distinguishes a genuine
"the query itself failed" branch from a "this pointer was never wired"
misconfiguration guard (`if (!store_ptr)`, which correctly carries NO retry
hint everywhere this was checked by hand during this script's own authoring).

WHAT THIS IS NOT: a proof. Same disclaimer as check-api-parity.py -- a lexical
tripwire, not a type-aware parse. A flagged branch that is legitimately
terminal (a "not found" lookup, an invalid-parameter parse) gets an inline
`// retry-hint-exempt: <reason>` comment on the SAME line as the
error_response/a4_error call, not a separate allowlist file -- keeping the
exemption next to the code it exempts is more auditable than a parallel list
that silently drifts.

USAGE:
    check-mcp-retry-hints.py <BASE> <HEAD> [--summary]

<BASE>/<HEAD> are git refs (matches check-plugin-readme-touch.sh's own
convention). The tool-name set is the symmetric difference of kTools[] entries
between BASE and HEAD, i.e. every NEW tool this change adds. (Tools this
change edits without adding are not in scope for THIS script by construction
--- kTools[] additions are grep-diffable; in-place edits to an existing
handler are not, and re-litigating every historical tool on every unrelated
touch is exactly the repo-wide-retrofit problem this script avoids. A
materially-changed EXISTING tool's retry-hint correctness is a governance
Gate-3/Gate-8 review question, not this script's job.)
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SERVER_CPP = "server/core/src/mcp_server.cpp"

KTOOLS_NAME = re.compile(r'^\s*\{"([a-z_][a-z0-9_]*)",', re.MULTILINE)

CALL_ASSIGNED_GUARD = re.compile(
    r"auto\s+(\w+)\s*=\s*[\w:>*.&()_,\s\-]*?\([^;]*\);"
    r"\s*(?:if\s*\(!\1(?:_or)?\)|if\s*\(!\1\.has_value\(\)\))"
    r"\s*\{([^{}]*)\}",
    re.DOTALL,
)

ERROR_CALL = re.compile(r"(error_response|a4_error|error_response_a4)\s*\(")
EXEMPT_COMMENT = re.compile(r"//\s*retry-hint-exempt:\s*\S")
TOOL_BLOCK_START = "if (tool_name == \"{name}\") {{"


def git_show(ref: str, path: str) -> str | None:
    try:
        return subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return None


def tool_names(text: str) -> set[str]:
    return set(KTOOLS_NAME.findall(text))


def find_tool_block(text: str, name: str) -> str | None:
    marker = TOOL_BLOCK_START.format(name=re.escape(name)).replace(re.escape(name), name)
    m = re.search(r'if \(tool_name == "' + re.escape(name) + r'"\) \{', text)
    if not m:
        return None
    start = m.end()
    depth = 1
    i = start
    while depth > 0 and i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[start:i]


def scan_block(name: str, block: str) -> list[tuple[str, str]]:
    """Return (varname, status) for every call-assigned error guard in one
    tool's handler block."""
    out = []
    for m in CALL_ASSIGNED_GUARD.finditer(block):
        varname, body = m.group(1), m.group(2)
        if not ERROR_CALL.search(body):
            continue
        if "retry_after_ms" in body:
            status = "ok"
        elif EXEMPT_COMMENT.search(body):
            status = "exempt"
        else:
            status = "gap"
        out.append((varname, status))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base", nargs="?", default="origin/dev")
    ap.add_argument("head", nargs="?", default="HEAD")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    base_src = git_show(args.base, MCP_SERVER_CPP)
    head_src = git_show(args.head, MCP_SERVER_CPP)
    if head_src is None:
        print(f"check-mcp-retry-hints: {MCP_SERVER_CPP} not found at {args.head}")
        print("check-mcp-retry-hints: FAIL (cannot verify the A5 retry-hint gate -- fail closed;")
        print("if the file genuinely moved, update MCP_SERVER_CPP in this script)")
        return 1  # fail CLOSED: an unreadable target must never look like a clean gate

    base_tools = tool_names(base_src) if base_src is not None else set()
    head_tools = tool_names(head_src)
    new_tools = sorted(head_tools - base_tools)

    if not new_tools:
        print(f"check-mcp-retry-hints: OK (no new MCP tools between {args.base} and {args.head})")
        return 0

    total_gaps = 0
    findings = []
    for name in new_tools:
        block = find_tool_block(head_src, name)
        if block is None:
            continue  # inline-builder tool with no dispatch-switch block; not this shape
        for varname, status in scan_block(name, block):
            findings.append((name, varname, status))
            if status == "gap":
                total_gaps += 1

    if args.summary:
        print(f"New tools in range ({len(new_tools)}): {', '.join(new_tools)}")
        for name, varname, status in findings:
            print(f"  {name}: var={varname} [{status}]")
        print()

    gaps = [f for f in findings if f[2] == "gap"]
    if gaps:
        print("check-mcp-retry-hints: new tool(s) have a store/query-fault error branch with")
        print("no retry_after_ms and no inline `// retry-hint-exempt: <reason>` comment:")
        for name, varname, _ in gaps:
            print(f"  {name} (guard variable: {varname})")
        print()
        print("Fix: pass retry_after_ms on the error_response/a4_error call (match the REST or")
        print("MCP twin's own value if one exists -- never invent a number). If this guard is")
        print("genuinely non-retryable (a \"not found\" lookup, an input-parse failure), add")
        print("`// retry-hint-exempt: <why>` on the error_response/a4_error line itself.")
        print(f"\ncheck-mcp-retry-hints: FAIL ({len(gaps)} new-tool gap(s))")
        return 1

    print(f"check-mcp-retry-hints: OK ({len(new_tools)} new tool(s), 0 unexempted gaps)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
