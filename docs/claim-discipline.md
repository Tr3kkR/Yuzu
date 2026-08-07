# Claim Discipline

Rules for prose that asserts a fact about the codebase or the product — commit
messages, code comments, docs, log/error/API strings, changelog fragments, issue and
PR bodies, governance ledger rows, agent handoffs — and for reviewing someone else's.

The failure this targets is mechanical, not a matter of carelessness: fix a defect,
write a prose explanation asserting facts (a measurement, another file's behavior, a
mechanism, a history, the sufficiency of a remedy), a reviewer checks one of those
facts and finds it wrong, a new round opens, and the correction adds more unverified
prose on top. Nobody asked for the assertions that started the loop — they get
volunteered.

**Each rule below names a TRIGGER — the moment you are about to do the thing — and a
CHECK you can perform.** A rule with no performable check is a slogan and does not
belong here. Rules also carry a **REVIEW CHECK**: the same rule applied by someone
reading a diff they did not write, which is a different exercise from checking your
own work — a reviewer has no working memory of where a citation came from and has to
rebuild it from scratch, which is exactly what makes a wrong-but-plausible citation
dangerous in the first place.

**This document does not state its own supporting counts, rates, or narratives.** A
rules file that invents its own evidence is the defect it exists to prevent. Where a
worked example is useful, it is drawn from a specific, named, closed governance
finding (see `docs/claim-discipline-patterns.txt`) rather than an aggregate claim.

**Rules are sorted by what actually goes wrong, not by topic.** Numbering is stable
across revisions of this document so that any future tuning can compare before and
after — do not renumber to close a gap. Rule 3 was retired (see below); its number is
not reused.

---

## 1. One fact, one home — and when you change a fact, find its other homes first

Authoring a duplicate is the smaller half of this failure. The sharper one is
**edit-time**: you correct, reword, or delete one copy of a fact and its siblings keep
asserting the old one. Surfaces are not just docs — they are code comments, API
message and remediation strings, `/metrics` HELP text, test docstrings, changelog
fragments, alert annotations, governance ledger rows, and GitHub issue bodies.

**TRIGGER:** you are about to change or delete a sentence that states a fact.
**CHECK:** before the edit, grep the fact's distinctive tokens across the whole
tree — not just the file type you are in — and list every home. Then change all of
them or none. Half a sweep is worse than none: it leaves the homes disagreeing, which
is how a reader learns which surface to distrust.

**Deleting is changing.** A cut orphans inbound pointers, and a cut that removes a
whole paragraph to kill one false clause takes true sentences with it. Remove the
false clause, keep the rest, and check what pointed at it.

**An issue is a home.** When a repo change makes a tracker issue's body wrong, the
fact still has one home and the issue is not exempt for not being a file.

**REVIEW CHECK (Gate 0):** for every fact-asserting sentence the diff **changed or
deleted**, recover its pre-change wording (`git show <base>:<path>`, `git log -p`) and
grep *that* wording's distinctive tokens tree-wide. Confirm every other site asserting
the old fact was updated in this same diff, or does not exist. A sibling site left
asserting the pre-change fact is a finding — this check is why Gate 0's scope cannot
be "diff-added lines only": the stale sibling is, by definition, untouched by the
diff.

## 2. A claim must be checkable from something you retrieved this session

**The source must be an artifact you retrieved this session, from the claim's
authoritative referent:** the file for a code claim, the PR for a head claim, the
tracker for an issue claim, the ledger for a disposition claim. All of these mean
retrieve-or-delete: "I remember," "an agent's report said it," "my earlier grep," "my
local checkout." **A null grep is not a retrieval** — for an absence claim, enumerate
the container.

This is the largest rule by miss count and is split into six named triggers. Apply the
ones the work touches; a generic "extract every sentence and list its source" pass
does not substitute for them.

### 2a. Same-file contradiction

The comment disagrees with a line in its own file, frequently within ten lines of
itself: a header asserting a build flag the build file three lines away disables, a
comment describing a conditional branch above a call that is unconditional, two
paragraphs of one changelog fragment saying opposite things.
**CHECK:** read the whole enclosing function or section, not the line you edited.
**REVIEW CHECK:** for every comment or doc paragraph the diff added or touched, read
the whole enclosing function/section and its sibling branches in the same file before
accepting the claim.

### 2b. Your own diff falsified it

The claim was true before this change. You moved, hoisted, inverted, or deleted the
thing it described and left the narrator standing. The commit that changes behavior is
the commit that must sweep its narrators.
**CHECK:** for every region you edited, re-read the comments in that region, then find
every artifact that quotes the thing you changed — test docstrings, changelog
fragments, metrics HELP, user docs, routed-concern rows.
**REVIEW CHECK:** for every region the diff touched, check whether an **unedited**
comment or doc elsewhere still describes the pre-change behavior. A stale narrator two
lines from an edited line is the highest-yield place to look.

### 2c. Mechanism or reachability asserted without walking the call graph

A dense class: "enforced at every mint surface" (one surface never calls it), "the
only place the anchor is written," "that path is unreachable" (a caller does reach
it), "X is checked at redemption" (a second redeemer skips it). A claim about **which
paths reach a function** is not checkable from inside that function, which is exactly
why it reads as safe to write there.
**CHECK:** grep the symbol, read every hit, and say how many you read. If you did not
walk them, write what the function does and not who reaches it.
**REVIEW CHECK:** grep the symbol yourself and read every hit independently of the
author's stated count. If the diff's own prose gives no count of sites checked, that
absence is itself a rule 5 finding ("say what you counted").

### 2d. An operator procedure whose mechanism you never retrieved

Runbooks, upgrade notes, incident guidance, recovery queries, alert annotations,
published SQL. The highest blast radius in this class: it is public, an operator acts
on it, and it outlives the session.
**CHECK:** run the query, or read the code that answers it. A procedure asserts the
product can complete it.
**REVIEW CHECK:** actually run the query or read the code path yourself before
accepting a runbook or remediation claim — do not accept "this works" on the author's
say-so for anything an operator will act on.

### 2e. Rotten retrieval

You did look it up, and the lookup was wrong. Shapes: a tool that silently excludes
part of the artifact (`gh issue view --json body` does not return comments); a cited
line that is real but sits inside a statement doing the opposite of what the citation
implies; a commit SHA cited after it was amended. **A wrong citation is worse than
none, because it survives review by looking checked.**
**CHECK:** does this tool see the whole artifact? Is the line I cite doing what I
think within its enclosing statement? Is this identifier still current?

Two mechanical checks are cheap and worth running over every citation the diff adds:

```bash
# Does the cited file exist, and does it have at least that many lines?
for c in $(git diff -U0 <base>...<tip> | grep '^+' \
           | grep -oE '[A-Za-z0-9_./-]+\.(cpp|hpp|h|cc|md|py|sh|yml):[0-9]+'); do
  f=${c%:*}; n=${c##*:}
  [ -f "$f" ] && [ "$(wc -l < "$f")" -ge "$n" ] || echo "BAD $c"
done

# Does every referenced doc path resolve? Same diff, same shape, without the line number.
```

A citation past EOF is always wrong. A citation to a **moved** line cannot be detected
this way, and pretending otherwise is itself a rule 5 defect.
**REVIEW CHECK:** run both loops above over the range under review before accepting
any citation in it.

### 2f. Universals

"The only," "none of," "every," "all three," "always," "cannot," "no path exists."
**CHECK:** sweep the prose you added for those words. For each, enumerate the set,
cite the code that closes it, or soften the sentence. Do not delete the sentence and
restate the same universal elsewhere — that reproduces the defect.

The concrete pattern list is `docs/claim-discipline-patterns.txt` — grep it against
**added lines only** (a whole-file run matches pre-existing tables and produces noise
that gets a check switched off):

```bash
git diff -U0 <base>...<tip> -- '*.md' '*.cpp' '*.hpp' '*.h' \
  | grep '^+' \
  | grep -Ei -f <(grep -v '^#' docs/claim-discipline-patterns.txt | grep .)
```

Its header carries two exemptions you must honor by reading them, not by re-encoding
them in the grep: a nearby file:line citation, and a `#!skip-files` directive for
design docs/ADRs, where an absence claim is a *requirement* for code that does not
exist yet, not an observation about code that does.
**REVIEW CHECK:** run the grep above over the diff under review, read every hit, and
confirm the enumeration/closure the sentence claims — or flag it.

### How to show your working

Before prose leaves your hands, list the fact-asserting sentences you added with
**where each fact came from**: sentence, source, verdict, one row each. No list means
the procedure did not run. Select on the assertion, not the citation — selecting only
sentences that name a file is blind to claims from memory, the riskier class: a wrong
citation is a typo, a wrong memory is an invention.

"Leaves your hands" means any of: a commit, a GitHub issue or comment, a PR body, a
brief handed to an agent, or a claim made straight to another person. There is no
automated check standing between you and any of these channels — this procedure is
the only thing that runs on any of them.

## 4. A ledger row is a claim, and its fields must agree with each other

**TRIGGER:** you are writing or superseding a ledger row, closing or parking an issue,
or recording a disposition.
**SECOND TRIGGER:** you are reporting on your own action anywhere else — "fixed" in a
commit message, a progress claim in a runtime log line, a status given straight to
another person in chat. Same test: retrieve the artifact that proves it (the commit,
the diff, the test output) and cite it. A false "fixed" said in chat leaves no file
for anyone to check it against, which makes it easier to write and no less wrong.

**CHECK,** against the row's own text and the artifact it points at:
- disposition vs stated facts: `rejected` on a row whose summary says the defect is
  real and unchanged is self-contradictory on its face.
- `severity_mapped` vs the row's own recorded impact and exposure. Severity is
  derived; a row that states the impact/exposure and then maps a lower band is wrong
  in the field, not in the derivation.
- `adjudicated_by` names a human who actually made that call — not the nearest
  authority.
- `commit_range` and `reviewed_at_sha` resolve, and are not empty ranges.
- a supersession under field-wise last-write-wins carries **every** field it means to
  change; an omitted field leaves the superseded value live.
- parking on an issue whose scope of work does not cover the finding lets the issue
  close as done with the defect live — read the scope before parking.
- "fixed" means retrieved-and-seen: the commit, the diff, or the test output.

**REVIEW CHECK (Gate 0):** for every governance ledger row or issue disposition the
diff adds or changes, run the checklist above against the row's own text and the
artifact it names — independently, not by re-reading the author's summary of it.

## 5. A check supports only the claim it actually tests

Rules 2 and 4 govern where a fact came from. This one governs the gap between the
check you ran and the conclusion you drew from it.
- A test's comment describes what the test **pins**, not what you hoped it pins.
  Prove it by mutation: break the thing, watch it go red. Untested, the comment is a
  claim like any other.
- A mutation that changes two things at once proves nothing about either.
- "Fires when it should" is not "fires only when it should." The negative arm is a
  separate test and usually the one that matters.
- A sample is not a sweep. If you checked 6 of 14 call sites, say 6 of 14.
- A keyword grep is not a closure proof. "Every surviving hit is fine" requires
  reading the hits.
- A wrong citation refutes the citation, not the finding.
- A count is a claim: say what you counted and what you excluded.
- A fix is a claim that it does not open a wider hole. Before calling a fix done, say
  what it now admits that it did not admit before.

**REVIEW CHECK (Gate 0):** for every claim in the diff that a test, check, or prior
run proves something, open that test/check yourself and confirm it demonstrates the
specific claim — not a related-but-different one. Treat an unstated sample size,
an unread grep-hit set, or an unstated "what does this fix now admit" as findings in
their own right.

## 6. A remedy, a scope, or a procedure claims to be sufficient

Not every defect in this class is a false statement — some are **incomplete** in a way
the reader cannot see. Shapes: a remediation that deletes a credential without
revoking what was minted with it; a mitigation step that is inert under a
configuration mode the prose never scoped out; an exposure note scoped to fewer
releases than actually carry the same path; a verification procedure that cannot
detect the state it claims to verify.

**Under-claiming is not the safe direction. It reads as an all-clear.**

**TRIGGER:** you are publishing a remedy, a verification step, an affected-version
range, or a precondition.
**CHECK:** state what it does *not* cover, or demonstrate that it covers everything.
For a remedy: what survives it? For a scope: what is just outside the boundary, and
why? For a verification step: what failure would it miss?

`docs/claim-discipline-patterns.txt` carries a sufficiency pattern block ("complete on
its own," "all you need," "nothing further is required") alongside the universals
block from rule 2f — sweep with 2f and you sweep for this rule too.

**REVIEW CHECK (Gate 0):** for every remedy, scope, or verification-step claim the
diff adds, check whether it states its own boundary. If it reads as complete with no
stated limit, actively look for the adjacent thing it does not cover before accepting
it — grep the sufficiency block in `docs/claim-discipline-patterns.txt` first, then
verify by reading, not by pattern match alone.

## 7. A documented interface is a claim about code

Rules 1 and 2 do not reach this class because the sentence is not false about any
file — it is false about the **product**. Shapes: a documented route that is
registered nowhere while other surfaces advertise it; a create-time field the handler
never reads, so a published example that means "disabled" produces an armed object; a
published endpoint list missing a field a documented rebuild requires.

**Existence is not enough. The route must be registered AND the field must be read.**

**TRIGGER:** you are documenting or citing a route, request field, flag, CLI verb, or
config key.
**CHECK:** cite the registration line and the line that consumes the value. If the
handler ignores the field, the documentation is a defect even when the field name is
spelled correctly.

**REVIEW CHECK (Gate 0):** for every documented route, field, flag, CLI verb, or
config key the diff adds or cites, find **both** the registration site and the
consuming/reading site yourself. A route registered but whose field is never read is a
finding even when every name in the documentation is spelled correctly.

---

## What these rules do not cover, deliberately

Code defects, false-green tests, severity-band derivation, and concurrent-agent
collisions are real failure classes but are not this one. Do not grow these rules to
chase them — they belong to the domain agents and the severity-derivation system that
already own them (see `CLAUDE.md` standing rule 2 and 3). Growing this document to
cover non-prose defects is how a focused check turns into a style guide nobody reads.

## Retired

**Rule 3** — "scope re-review by what the fix diff actually contains; a text-only fix
gets the docs reviewer alone" — was retired after a cheap-roster version of this rule
would have missed most of the blocking findings on the branch that motivated it. It
optimized for review cost, and the cost was buying something. Its number is not
reused; do not reinstate the idea without evidence that a cheap roster finds what the
full one finds.

## The re-read, before anything leaves your hands

Re-read every sentence you added and ask: **could a reviewer falsify this from the
repo?** If yes, and you have not checked it yourself, check it or cut it. That re-read
is the test. Nothing else runs automatically on any channel this document covers.
