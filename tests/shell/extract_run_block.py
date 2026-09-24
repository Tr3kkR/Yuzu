#!/usr/bin/env python3
"""Extract one workflow step's `run: |` body, de-indented, for a hermetic shell test.

The tests under tests/shell/ execute the REAL step bodies out of the workflow
files rather than a copy, so they cannot drift into asserting a duplicate of the
logic instead of the logic. Select the step with `--id <step id>` or
`--name <step name>`; the body is every following line indented deeper than
`run:` (the next `- ` step would overshoot into the job's `outputs:` block).

`--subst 'github.expr=VAR'` rewrites `${{ github.expr }}` to `$VAR` so the
harness can drive it; any other `${{` left in the body is an error, because the
shell cannot evaluate it and a silent leftover would make the test vacuous.

`--job JOB` restricts the search to that top-level job (a step name such as `Test (non-pg suites)`
repeats across the linux, windows and macos jobs), and `--nth N` takes the Nth match inside the window.

Usage: extract_run_block.py <workflow.yml> <out.sh> (--id ID | --name NAME) [--job JOB] [--nth N]
                            [--subst EXPR=VAR ...]
"""

from __future__ import annotations

import argparse
import re
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("workflow")
    ap.add_argument("out")
    sel = ap.add_mutually_exclusive_group(required=True)
    sel.add_argument("--id")
    sel.add_argument("--name")
    ap.add_argument("--job")
    ap.add_argument("--nth", type=int, default=1)
    ap.add_argument("--subst", action="append", default=[])
    args = ap.parse_args()

    lines = open(args.workflow, encoding="utf-8").read().split("\n")
    marker = f"- id: {args.id}" if args.id else f"- name: {args.name}"
    lo, hi = 0, len(lines)
    if args.job:
        header = f"  {args.job}:"
        found = [n for n, line in enumerate(lines) if line.rstrip() == header]
        if not found:
            print(f"job {args.job!r} not found in {args.workflow}", file=sys.stderr)
            return 2
        lo = found[0]
        hi = next((n for n in range(lo + 1, len(lines)) if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[n])),
                  len(lines))
    matches = [n for n in range(lo, hi) if lines[n].strip() == marker]
    if len(matches) < args.nth:
        print(f"step {marker!r} (occurrence {args.nth}) not found in {args.workflow}"
              + (f" job {args.job!r}" if args.job else ""), file=sys.stderr)
        return 2
    start = matches[args.nth - 1]
    try:
        run = next(n for n in range(start, hi) if lines[n].strip() == "run: |")
    except StopIteration:
        print(f"step {marker!r} has no `run: |` block in {args.workflow}", file=sys.stderr)
        return 2
    indent = len(lines[run]) - len(lines[run].lstrip()) + 2
    body: list[str] = []
    for line in lines[run + 1:]:
        if line.strip() == "":
            body.append("")
            continue
        if len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:])
    text = "\n".join(body)
    for subst in args.subst:
        expr, var = subst.split("=", 1)
        text = text.replace("${{ " + expr + " }}", "$" + var)
    leftover = [line for line in text.split("\n") if "${{" in line]
    if leftover:
        print("unsubstituted GitHub expression in the extracted body:\n" + "\n".join(leftover), file=sys.stderr)
        return 2
    if not text.strip():
        print("extracted body is empty", file=sys.stderr)
        return 2
    open(args.out, "w", encoding="utf-8").write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
