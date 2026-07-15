#!/usr/bin/env python3
"""
issue-standard-guard.py -- PreToolUse hook: hold `gh issue create` to the
issue-lifecycle standard (docs/agents/issue-standard.md, ADR-3001 pillar 4).

Fires on Bash/PowerShell tool calls (matcher Bash|PowerShell in
.claude/settings.json). It does nothing unless the command actually contains a
`gh issue create` invocation, so the common case -- any other shell command --
is a stdin-parse + one cheap regex and returns immediately.

What it enforces, and why only these three things (ADR-3001 A1, "PR 3"):

  * LABELS -- enforceable. `gh issue create` has no `--label-file`, so every
    label is a literal `--label`/`-l` token in the command string. The gh/agent
    path of the standard (section 4) is: exactly one TYPE, and then either
    `roadmap` (parked scope: no priority, no triage state) XOR one PRIORITY
    (P0/P1/P2) alongside one TRIAGE STATE. Automation-owned labels are never set
    at filing. A contract violation -> deny with the exact fix.

  * SECURITY label -> ask (never silently allow, never hard-deny). A public
    `security` issue is hardening/defense-in-depth ONLY; an *exploitable*
    vulnerability must go through private advisory reporting (SECURITY.md),
    never a public issue. Only a human can make that call, so we surface it.

  * DEDUPE -- read from the SESSION TRANSCRIPT, not the current command. The
    standard (section 2) makes a duplicate search mandatory before filing. The
    transcript records what actually ran, so this is far harder to fake than
    inspecting the create command itself (which an agent controls): a probe has
    to have executed earlier in the session as a real `gh search issues` /
    `gh issue list --search` tool call. No probe seen -> ask (a legitimate
    out-of-band dedupe is possible, so we confirm rather than block).

  BODY is deliberately best-effort. `--body-file -`, heredocs and `$VAR` all
  defeat static inspection, so the body-section check applies ONLY when the body
  is a literal token, and even then it only asks; when unresolvable it is
  skipped, never denied.

Shell parsing is quote- and boundary-aware (see _split_shell_segments): the
command is sliced into simple commands at UNQUOTED `;`, `&`, `|`, `&&`, `||` and
newlines BEFORE tokenising each segment, so a second create on the next line
cannot mask a bad first one and a quoted operator (`--title ";"`) cannot
truncate the flag list. A heredoc / `--body-file -` body sits on its own lines,
which become their own (non-create) segments and are ignored -- deliberately
WITHOUT a naive heredoc pre-strip, which misread a `<<` inside a quoted body
(`cout << x`, a bit-shift, an Erlang `<<Bin>>`) as a redirect and corrupted the
command. Line continuations are normalised first. Anything still mis-sliced
degrades to a segment shlex rejects -> fail-open.

Design (matches changelog-fragment-guard.py -- the PreToolUse sibling, NOT
erl-dialyzer-reminder.py's Stop-hook `{"decision":"block"}` shape):
  - Fail-open: ANY ambiguity or error -> allow (no output, exit 0). A convention
    hook must never wedge a session; the close-on-merge workflow and PR review
    are the server-side backstops.
  - UTF-8 explicit on stdin and the transcript (never inherit cp1252 on Windows;
    see memory reference_hookify_ascii_only).
  - ALWAYS exit 0; the decision is carried in the JSON, never the exit code.
  - Claude sessions only. Other agents and humans remain bound by the text of
    the standard and by PR review.
"""
import json
import os
import re
import shlex
import sys

SHELL_TOOLS = ("Bash", "PowerShell")

STD = "docs/agents/issue-standard.md"
ADVISORY_URL = "https://github.com/Tr3kkR/Yuzu/security/advisories/new"

# Bound work before the O(n^2) shlex tokeniser runs. A real `gh issue create`
# command line is a few KB at most; anything larger fails open (a huge body
# belongs in --body-file anyway). Guards against a crafted megabyte-long token
# stalling the hook (which blocks the tool call synchronously).
MAX_COMMAND_LEN = 20_000

# Cheap pre-filter run on EVERY shell command. Regex, not a fixed-space
# substring, so `gh   issue   create` (a shell collapses the whitespace) is not
# a silent bypass; case-insensitive and `.exe`/`.cmd`-aware so `gh.exe issue
# create` on Windows is not a bypass either. Permissive on purpose -- the real
# parser decides; a false hit only costs one wasted tokenise.
_CREATE_GATE = re.compile(r"gh(?:\.exe|\.cmd)?\s+issue\s+create\b", re.IGNORECASE)

# Line continuation `\<newline>` -- a shell removes it entirely, so we normalise
# it away before the gate/parser (else it splits the `gh issue create` phrase).
_LINE_CONT = re.compile(r"\\\r?\n")

# Label taxonomy -- docs/agents/triage-labels.md. Lower-case; labels are
# casefolded before comparison because GitHub resolves label names
# case-insensitively (so `--label SECURITY` applies the real `security` label).
TYPE_LABELS = frozenset({
    "bug", "enhancement", "task", "decision",
    "spike", "documentation", "question", "operational",
})
TRIAGE_STATES = frozenset({
    "needs-triage", "needs-info", "ready-for-agent", "ready-for-human", "wontfix",
})
PRIORITIES = frozenset({"p0", "p1", "p2"})
AUTOMATION_OWNED = frozenset({
    "do-not-close", "fixed-on-dev", "automation-broken",
    "triage-sweep", "nightly-broken", "runner-inventory-drift",
})
ROADMAP = "roadmap"
SECURITY = "security"

# Body sections mandated by the standard section 3, in order.
BODY_SECTIONS = ("Context", "Evidence", "Acceptance criteria", "Origin")


def _is_unresolvable(value):
    """True if a --body value cannot be inspected statically (var/subst/stdin)."""
    if value in ("-", ""):
        return True
    return "$" in value or "`" in value


def _split_labels(value):
    """`bug,P1,needs-triage` -> ['bug','P1','needs-triage'] (drops empties)."""
    return [p.strip() for p in value.split(",") if p.strip()]


def _split_shell_segments(command):
    """Slice a command into simple-command segments at UNQUOTED separators.

    Splits on `;`, `&`, `&&`, `|`, `||` and newlines that are outside single
    quotes, double quotes and backticks. A quoted operator (e.g. inside
    `--title ";"`) is therefore NOT a boundary, and a create on the next line
    does not merge into the previous one. A heredoc body sits on its own lines,
    which become their own segments here and are dropped downstream because they
    are not a `gh issue create`. Escapes are honoured outside single quotes and
    inside double quotes/backticks.
    """
    segments = []
    buf = []
    quote = None  # "'", '"', "`" or None
    i = 0
    n = len(command)
    while i < n:
        c = command[i]
        if quote:
            if c == "\\" and quote != "'" and i + 1 < n:
                buf.append(c)
                buf.append(command[i + 1])
                i += 2
                continue
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(command[i + 1])
            i += 2
            continue
        if c in ("'", '"', "`"):
            quote = c
            buf.append(c)
            i += 1
            continue
        if c in ("\n", ";"):
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        if c == "&":
            segments.append("".join(buf))
            buf = []
            i += 2 if (i + 1 < n and command[i + 1] == "&") else 1
            continue
        if c == "|":
            segments.append("".join(buf))
            buf = []
            i += 2 if (i + 1 < n and command[i + 1] == "|") else 1
            continue
        buf.append(c)
        i += 1
    segments.append("".join(buf))
    return segments


def _is_gh_token(tok):
    """True if a token invokes gh: `gh`, `gh.exe`, `gh.cmd`, or a path to one."""
    base = tok.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    return base in ("gh", "gh.exe", "gh.cmd")


def _find_create_arg_lists(command):
    """Return the flag-token list for every real `gh issue create` invocation.

    Segments the command first (so operators/newlines/heredocs are handled),
    then within each segment finds `gh` `issue` `create` as three contiguous
    tokens (a path-prefixed `/usr/bin/gh` counts; a create only inside a quoted
    string does not, since it is one token). A segment shlex cannot parse is
    skipped -> fail-open.
    """
    out = []
    for segment in _split_shell_segments(command):
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            continue  # unbalanced quotes etc. -> skip this segment
        i, n = 0, len(tokens)
        while i < n:
            if (
                _is_gh_token(tokens[i])
                and i + 2 < n
                and tokens[i + 1] == "issue"
                and tokens[i + 2] == "create"
            ):
                out.append(tokens[i + 3:])
                i += 3
            else:
                i += 1
    return out


def _parse_create_flags(args):
    """Extract (labels, body, body_resolvable, web, is_help) from a create's flags.

    Handles `-l x`, `-lx`, `--label x`, `--label=x`, comma lists and repeats for
    labels; `-b`/`--body`(`=`) for the body; `-F`/`--body-file`(`=`), `-e`/
    `--editor` and any var/subst body as unresolvable; `-w`/`--web` (browser
    form sets labels interactively) and `-h`/`--help` as skip signals.
    """
    labels = []
    body = None
    body_resolvable = True
    web = False
    is_help = False
    i, n = 0, len(args)
    while i < n:
        tok = args[i]
        if tok in ("-l", "--label"):
            if i + 1 < n:
                labels.extend(_split_labels(args[i + 1]))
                i += 2
                continue
            i += 1
            continue
        if tok.startswith("--label="):
            labels.extend(_split_labels(tok[len("--label="):]))
            i += 1
            continue
        # Glued short form `-lbug`. (`--label` is caught above and never reaches
        # here; only a `-l...` short cluster does.)
        if tok.startswith("-l") and len(tok) > 2 and not tok.startswith("--"):
            labels.extend(_split_labels(tok[2:]))
            i += 1
            continue
        if tok in ("-b", "--body"):
            if i + 1 < n:
                val = args[i + 1]
                if _is_unresolvable(val):
                    body_resolvable = False
                else:
                    body = val
                i += 2
                continue
            i += 1
            continue
        if tok.startswith("--body="):
            val = tok[len("--body="):]
            if _is_unresolvable(val):
                body_resolvable = False
            else:
                body = val
            i += 1
            continue
        if tok in ("-F", "--body-file"):
            body_resolvable = False
            i += 2 if i + 1 < n else 1
            continue
        if tok.startswith("--body-file="):
            body_resolvable = False
            i += 1
            continue
        if tok in ("-e", "--editor"):
            body_resolvable = False
            i += 1
            continue
        if tok in ("-w", "--web"):
            web = True
            i += 1
            continue
        if tok in ("-h", "--help"):
            is_help = True
            i += 1
            continue
        i += 1
    return labels, body, body_resolvable, web, is_help


def _evaluate_labels(labels):
    """Return (deny_reasons, ask_reasons) for one create's label set.

    Labels are casefolded so a mis-cased `SECURITY`/`DO-NOT-CLOSE` (which GitHub
    applies as the real label) still trips the security/automation checks.
    """
    deny = []
    ask = []
    label_set = {lbl.casefold() for lbl in labels}
    types = sorted(label_set & TYPE_LABELS)
    states = sorted(label_set & TRIAGE_STATES)
    prios = sorted(label_set & PRIORITIES)
    autos = sorted(label_set & AUTOMATION_OWNED)
    has_roadmap = ROADMAP in label_set

    # exactly one type (any path)
    if len(types) == 0:
        deny.append(
            "no TYPE label -- add exactly one of: "
            + ", ".join(sorted(TYPE_LABELS))
        )
    elif len(types) > 1:
        deny.append(f"multiple TYPE labels {types} -- keep exactly one")

    # roadmap XOR (priority + triage state), on the gh path
    if has_roadmap:
        if prios:
            deny.append(
                f"`roadmap` carries no priority -- remove {prios} "
                "(parked scope is not prioritised)"
            )
        if states:
            deny.append(
                f"`roadmap` carries no triage state -- remove {states} "
                "(parked scope is excluded from triage)"
            )
    else:
        if len(prios) == 0:
            deny.append(
                "no PRIORITY -- the gh/agent path sets one of P0/P1/P2 "
                "(or use `roadmap` for parked scope)"
            )
        elif len(prios) > 1:
            deny.append(f"multiple PRIORITY labels {prios} -- keep exactly one")
        if len(states) == 0:
            deny.append(
                "no TRIAGE STATE -- add exactly one of: "
                + ", ".join(sorted(TRIAGE_STATES))
            )
        elif len(states) > 1:
            deny.append(f"multiple TRIAGE STATE labels {states} -- keep exactly one")

    # automation-owned labels are never set at filing
    if autos:
        deny.append(
            f"automation-owned label(s) {autos} must not be set at filing -- "
            "automation applies them (a maintainer may add `do-not-close` later "
            "via `gh issue edit`)"
        )

    # security -> ask (a human must confirm public-issue eligibility)
    if SECURITY in label_set:
        ask.append(
            "carries the `security` label. PUBLIC security issues are "
            "hardening / defense-in-depth ONLY -- an exploitable vulnerability "
            f"goes through PRIVATE advisory reporting ({ADVISORY_URL}), never a "
            "public issue (SECURITY.md, standard section 6). Confirm this is "
            "non-exploitable before filing."
        )
    return deny, ask


def _evaluate_body(body, body_resolvable):
    """Best-effort body-section check. Returns ask_reasons (never deny)."""
    if not body_resolvable or body is None:
        return []  # unresolvable -> skip, never deny
    missing = [
        s for s in BODY_SECTIONS
        if not re.search(r"(?mi)^#{1,6}\s*" + re.escape(s) + r"\b", body)
    ]
    if missing:
        return [
            "body is missing required section(s) "
            f"{missing} -- the standard (section 3) wants "
            "## Context / ## Evidence (with file:line) / "
            "## Acceptance criteria / ## Origin"
        ]
    return []


def _is_search_flag(tok):
    """A real search flag token: --search, --search=x, -S, or glued -Sx."""
    return (
        tok == "--search"
        or tok.startswith("--search=")
        or tok == "-S"
        or (tok.startswith("-S") and len(tok) > 2)
    )


def _looks_like_probe(command):
    """True if a command tokenises to a real dedupe search.

    Tokenised (not substring): `gh ... search issues`, or `gh ... issue list`
    with a real `--search`/`-S` flag TOKEN. Position-independent so global flags
    before the subcommand (`gh --repo X issue list --search y`) still count, and
    glued short forms (`-Sfoo`) count. Rejects a probe mentioned only inside a
    quoted string/comment (it would be one token) and `-S` inside an unrelated
    value like `Foo-Section` (that is not a standalone token).
    """
    try:
        toks = shlex.split(command, posix=True)
    except ValueError:
        return False
    if not any(_is_gh_token(t) for t in toks):
        return False
    n = len(toks)
    # `search issues` as a contiguous pair
    if any(toks[i] == "search" and toks[i + 1] == "issues" for i in range(n - 1)):
        return True
    # `issue list` as a contiguous pair, plus a search flag anywhere
    if any(toks[i] == "issue" and toks[i + 1] == "list" for i in range(n - 1)):
        if any(_is_search_flag(t) for t in toks):
            return True
    return False


def _iter_tool_commands(transcript_path):
    """Yield the command string of every shell tool_use in the transcript."""
    with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = rec.get("message", rec)
            content = msg.get("content") if isinstance(msg, dict) else None
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    if block.get("name") in SHELL_TOOLS:
                        yield str((block.get("input") or {}).get("command") or "")


def _dedupe_probe_seen(transcript_path):
    """True if a duplicate-search probe ran earlier this session.

    Fail-open: if the transcript cannot be read we return True (no ask) rather
    than nagging on our own inability to inspect.
    """
    if not transcript_path:
        return True
    transcript_path = os.path.expanduser(transcript_path)
    if not os.path.isfile(transcript_path):
        return True
    try:
        for cmd in _iter_tool_commands(transcript_path):
            if "gh" in cmd and _looks_like_probe(cmd):
                return True
    except Exception:
        return True  # fail-open
    return False


def _emit(decision, reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))


def main():
    try:
        raw = sys.stdin.buffer.read()
        data = json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
    except Exception:
        return  # fail-open

    if not isinstance(data, dict) or data.get("tool_name") not in SHELL_TOOLS:
        return
    tool_input = data.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return
    command = _LINE_CONT.sub("", command)  # a shell removes `\<newline>` entirely
    if not _CREATE_GATE.search(command):
        return  # cheap gate -- the vast majority of shell calls stop here
    if len(command) > MAX_COMMAND_LEN:
        return  # oversized -> fail-open (avoids the shlex O(n^2) path)

    create_arg_lists = _find_create_arg_lists(command)
    if not create_arg_lists:
        return  # `gh issue create` only inside a quoted string -> not a real create

    deny_reasons = []
    ask_reasons = []
    real_creates = 0
    for args in create_arg_lists:
        labels, body, body_resolvable, web, is_help = _parse_create_flags(args)
        if web or is_help:
            continue  # browser form / help -> nothing to enforce here
        real_creates += 1
        d, a = _evaluate_labels(labels)
        deny_reasons.extend(d)
        ask_reasons.extend(a)
        ask_reasons.extend(_evaluate_body(body, body_resolvable))

    if real_creates == 0:
        return  # every create was --web/--help

    # Dedupe is session-level, evaluated once for the whole command.
    if not _dedupe_probe_seen(data.get("transcript_path")):
        ask_reasons.append(
            "no duplicate-search probe (`gh search issues` or "
            "`gh issue list --search`) was seen in this session before this "
            "filing. The standard (section 2) requires a dedupe search. Confirm "
            "you checked for duplicates, or run a probe first."
        )

    # deny wins over ask wins over allow.
    if deny_reasons:
        # de-dupe while preserving order (several creates can raise the same reason)
        seen = set()
        uniq = [r for r in deny_reasons if not (r in seen or seen.add(r))]
        bullets = "\n".join(f"  - {r}" for r in uniq)
        _emit(
            "deny",
            "This `gh issue create` does not meet the issue-lifecycle standard "
            f"({STD}, ADR-3001 section 4):\n{bullets}\n\n"
            "Fix the --label flags and retry. Full label contract: "
            "docs/agents/triage-labels.md.",
        )
        return
    if ask_reasons:
        seen = set()
        uniq = [r for r in ask_reasons if not (r in seen or seen.add(r))]
        bullets = "\n".join(f"  - {r}" for r in uniq)
        _emit(
            "ask",
            f"This `gh issue create` needs a human check ({STD}):\n{bullets}",
        )
        return
    # otherwise allow (emit nothing)


if __name__ == "__main__":
    try:
        main()
    finally:
        sys.exit(0)  # ALWAYS exit 0 -- decision is in the JSON, never the exit code
