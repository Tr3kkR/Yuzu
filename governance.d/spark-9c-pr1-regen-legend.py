import sys,re
p=sys.argv[1]; lines=open(p).read().split("\n")
rows=[l for l in lines if l.startswith("| ") and not l.startswith("| # ") and not l.startswith("|---") and not l.startswith("| test |")]
nomatch=[l for l in rows if "rc=2 (no summary)" in l]
valid=[l for l in rows if l not in nomatch]
RED=re.compile(r"FAILED|SIGABRT|rc=42|sig=6|unexpected exception|rc=-11|died|terminate", re.I)
GRN=re.compile(r"All tests passed|green|rc=0|passed \(|\d+ passed", re.I)
red=[l for l in valid if RED.search(l)]; green=[l for l in valid if GRN.search(l)]
pairs=[l for l in valid if RED.search(l) and GRN.search(l)]
legend=(f"**Legend (computed from the rows below by `scratchpad/regen-legend.py`; method: a data row is any `| ` line outside the header/separator rows, classified on its WHOLE text because Catch2 output inside cells contains literal pipes; "
        f"a no-match row reads `rc=2 (no summary)`; RED = the row names a FAILED / SIGABRT / rc=42 / unexpected-exception / rc=-11 line; GREEN = the row names a pass (`All tests passed`, `N passed`, `rc=0`, `green`); a completed pair is a row that is both):** "
        f"{len(rows)} data rows; {len(nomatch)} matched no test (Catch2 comma split, each superseded by its wildcard re-run row); "
        f"{len(valid)} valid rows; {len(red)} RED; {len(green)} GREEN; **{len(pairs)} completed red-then-green pairs** "
        f"(the figure the PR body quotes; adversarial round 4 C2/K1 recount adopted: earlier legends counted rows, not pairs; the {len(valid)-len(pairs)} non-pair rows are observed-only or first attempts that a later row completes).")
open(p,"w").write("\n".join(legend if l.startswith("**Legend (computed from the rows below") else l for l in lines))
print(f"rows={len(rows)} valid={len(valid)} red={len(red)} green={len(green)} pairs={len(pairs)}")
