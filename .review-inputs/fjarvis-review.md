## Adversarial review (Codex + Kimi, two-phase) — REQUEST CHANGES

Two independent reviewers, two phases, then I verified every claim myself by running it. **The three headline claims all check out** — but two things are broken in ways that are one-line fixes, and both are of exactly the class this PR exists to eliminate. That is the only reason I'm asking for changes on a 52-line docs PR rather than approving.

Codex returned BLOCK in both phases. Kimi returned PASS, having withdrawn its own correct finding — more on that below, because the way it happened is worth knowing.

### First, what I verified rather than took on trust

Since the PR's own rule is *check, don't recall*, I ran the currency check verbatim in three trees:

| tree | result |
|---|---|
| checked out before `.claude/routed-concerns.md` existed — **the exact #2604 failure**, file absent locally, present on `origin/dev` | **STALE** ✓ |
| at `origin/dev` | **current** ✓ |
| this PR's head | **STALE** ✓ — the disclosed intended direction |

So the check does catch the case it was written for, including absence, which was the subtle one. Also confirmed: `<run-log-dir>` was exactly 1 occurrence at the merge base and is 0 at head; all four standing rules are faithful to the skill (R1 `SKILL.md:92,94,463,951`; R2 `:112,130-131`; R3 `:133,146,148`; R4 `:36,855-881`, #2580 account included); all four ledger field names exist; `.changed` is a valid section; CLAUDE.md is under the ceiling.

And **"no domain agent is routed" is right.** My first grep found 4 hits for `CLAUDE.md|.claude/skills` in the routed table, which looked like a contradiction — but none is a row *key*: two are the header comment and two are doc-pointer cells whose triggers are unrelated. Kimi argued `docs-writer` is unconditional and therefore the claim is false; that's a vocabulary quibble, and you used the skill's own vocabulary, which distinguishes mandatory Gate-2 agents from Gate-3 domain triggers.

### 1. The ledger default path lands *inside the repo* when quoted

`${YUZU_GOV_LOG_DIR:-~/.local/share/yuzu/governance-runs}` — measured with the variable unset:

| form | result |
|---|---|
| `mkdir -p ${...:-~/...}` unquoted | expands correctly to `$HOME/.local/share/yuzu/...` |
| `mkdir -p "${...:-~/...}"` **quoted** | creates a literal **`./~/.local/share/yuzu/...` under the CWD** |

Tilde expansion doesn't happen inside double quotes. Quoting a path is the standard safe-shell habit and the likelier rendering by an LLM following a runbook — and the skill explicitly says "Create the directory if absent", so the `mkdir` definitely happens. For a governance run the CWD is the repo, so the ledger lands **in the working tree**, isn't ignored, can be committed, and does **not** survive `git clean` — the exact inverse of the stated rationale.

`/test`, the precedent you cite, uses `$HOME` and doesn't have this problem. Fix is one word: `~` → `$HOME`, in both `SKILL.md` and `CLAUDE.md`.

### 2. `<n>` is undefined — the fix for one undefined placeholder contains another

`run_id` is `gov-<UTC date>-<short base sha>-<n>`, with one example (`-1`) and no rule for deriving, incrementing or no-clobbering it. Two runs on the same base on the same UTC date — routine, since Gate 8 iterates — both plausibly pick `-1`, and the second overwrites or appends into the first.

Codex and Kimi reached this independently. What makes it worth fixing rather than noting is that it's the same failure mode you're fixing: `<run-log-dir>` had no defined home, and the replacement has a defined directory but an undefined filename. In a runbook consumed by an LLM, an unspecified component gets resolved differently every run.

The precedent you're citing already solves it — `/test` uses `RUN_ID="$(date +%s)-$$"`, collision-free by construction with no existence probing. Right now the PR mirrors `/test`'s *location* but not its *id derivation*, and the id derivation is the part that avoids this. Either adopt that form, or define `<n>` as the lowest integer whose path doesn't exist plus no-clobber creation.

I've graded this MEDIUM rather than Codex's HIGH, because the skill explicitly disclaims the artifact ("no database and no shared store yet ... Do not describe it as more than it is") — so what's lost is a re-creatable working file, not change-control evidence.

### 3. Worth fixing while you're in there

**The currency check omits `CLAUDE.md`.** It covers the skill and the routed-concerns table, but not the file this PR is simultaneously editing to carry the standing rules — and which the skill's own header calls the thing it is a runbook for ("the pipeline **defined in CLAUDE.md**"). Your own argument is that CLAUDE.md staleness matters most: "loaded into every session, so a stale summary there outranks a correct skill in practice." Codex's counter is fair (the skill is the executable runbook, CLAUDE.md a summary), so this is a judgment call — but the reasoning picks CLAUDE.md as the highest-leverage stale file and then leaves it out of the guard. Add it, or say in a clause why not.

**A failed `git fetch` gives a silent false "current."** `git fetch origin dev -q` is a bare statement whose exit status is discarded, so if it fails — offline, VPN, expired auth, rate limit — the diff runs against the last cached `origin/dev`. I demonstrated it in an isolated synthetic repo: remote unreachable (fetch exits 128, discarded), cached ref matching the tree, and the check prints **"governance assets current"** while the tree holds the old pipeline. That's the one direction the check exists to prevent, and you deliberately chose the opposite direction as safe elsewhere. `git fetch origin dev -q || echo "WARNING: fetch failed - origin/dev may be stale"` closes it.

Minor, same area: the remedy text ("read the two files from `origin/dev` directly and use those") is self-defeating for a branch whose purpose is editing them — like this one. A one-clause carve-out would help.

**Nit:** "25.9k characters" is the byte count. `wc -m` gives 25,692 characters, `wc -c` gives 25,899 bytes. Nothing turns on it, but in a PR about checking claims the unit is worth matching.

### On the panel — a harness bug of mine, not yours

Kimi's first pass couldn't verify the currency-check syntax because it received `{{CONTEXT}}{{CONTEXT}} echo` where your file has `&& echo`, and "Enterprise A{{CONTEXT}}A roadmap" for "A&A".

That was **my tooling corrupting the bundle**, not anything in your PR. The driver substitutes with `body="${body//\{\{CONTEXT\}\}/$CONTEXT}"`, and bash ≥5.2 turns on `patsub_replacement` by default, under which an unescaped `&` in the replacement expands to the matched text. So every `&` in every bundle became `{{CONTEXT}}`. I re-ran both Kimi phases against a patched driver and used only the clean output; flagging it because it means my Kimi leg has been reading corrupted source, and the finding in section 1 only appeared once the input was clean.

The Kimi/Codex split on that finding is also worth recording: Kimi raised it, then **withdrew it** in phase 2 on the strength of Codex's phase-1 note that the default "expands to `/home/fraser/...`" — which had tested only the unquoted form. Codex's phase 2 then reproduced the quoted form and confirmed it. So the originator dropped a correct finding on incomplete peer evidence while the peer was busy confirming it. Measuring both quoting forms is what settles it independently of either.

---

None of this touches the substance: the currency check works, the diagnosis behind it is right, and the standing rules faithfully restate the skill. It's two one-line fixes and a judgment call. Happy to re-review as soon as they're up.

