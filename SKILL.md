---
name: scanme
description: >
  Security audit for web apps and AI-assisted / "vibe coded" codebases that
  reports only vulnerabilities it has actually proven, and fixes them with a
  regression test that fails before the fix and passes after. Use whenever the
  user asks for a security audit, penetration-style review, vulnerability scan,
  "find security issues", "is my app safe to ship", "harden this", "check for
  loopholes", "audit my codebase before launch", or wants exposed secrets, SQL
  injection, XSS, IDOR/broken access control, SSRF, or auth bypasses found and
  fixed. Also use when a previous scanner produced a pile of findings and the
  user wants to know which ones are real. Covers reachability analysis,
  exploit reproduction, and verified remediation — it will not report a finding
  it cannot demonstrate.
---

# scanme

## The one rule

**A finding does not exist until you have proven it.**

Every security scanner in existence produces lists. Lists are cheap, and most
entries on them are wrong — a `dangerouslySetInnerHTML` fed by a hardcoded
constant, an `eval` in a dev-only script, a "critical" CVE in a transitive
dependency that never executes. Developers learn to ignore these lists, which
means real vulnerabilities buried inside them get ignored too. That is the
actual harm: false positives don't just waste time, they train people not to
look.

So this audit inverts the usual tradeoff. Finding fewer issues is not a
failure mode here. Reporting one proven, reproducible vulnerability with a
working demonstration is worth more than forty maybes, because the developer
can act on it immediately and without doubting you.

If you cannot prove something, you do not report it as a vulnerability. You
put it in the unverified-leads appendix and say plainly that you could not
confirm it. That honesty is the product.

## Scope and authorization

Audit **code and systems the user controls** — their repository, their local
or staging instance. Reproductions run against a local or explicitly
user-provided test instance, never against production without the user saying
so, and never against a third party's site.

If the user asks you to point this at a domain they haven't indicated they
own or are authorized to test, stop and ask. Unauthorized scanning is a legal
problem for them, not a thoroughness win. This isn't a formality — a request
like "audit example.com for me" needs an explicit "yes, I own this / I have
written authorization" before any active probing.

Static review of source code the user hands you is always fine.

## Workflow

### Phase 0 — Load prior state

Findings live in a SQLite ledger at `.scanme/findings.db`, not only in a
Markdown file. The ledger is what gives a finding identity across runs, so
questions a report can't answer — *is this new? did our fix hold?* — have real
answers.

```bash
python scripts/findings.py --root <project> stats
python scripts/findings.py --root <project> list --status open
```

If the store exists:
- **`regressed` findings are your top priority.** A finding marked fixed that
  reappeared means a security fix silently reverted, which is the most
  dangerous state a codebase can be in — the team believes it is closed.
- `proven` findings that are still open: fix them (Phase 4), don't re-prove.
- `candidate` findings: these are unproven leads waiting on Phase 3.
- `discarded` findings: do not re-raise. The reason is recorded; respect it
  unless the code at that location has changed.

Also read `SECURITY_AUDIT.md` if present for the narrative context and the
prior attack-surface inventory — use it as the starting map for Phase 1 rather
than rebuilding from scratch.

If neither exists, this is a first run; continue to Phase 1.

### Phase 1 — Map the attack surface

You cannot find what you haven't mapped, and hunting vulnerability-by-
vulnerability through a codebase you don't understand produces exactly the
noisy output this skill exists to avoid. Spend real effort here first.

Read [references/attack-surface.md](references/attack-surface.md).

You are building an inventory of:
- **Entry points** — every place attacker-controlled data enters (HTTP routes,
  form handlers, webhooks, file uploads, query params, headers, cookies,
  websocket messages, third-party callbacks).
- **Trust boundaries** — where data crosses from untrusted to trusted context
  (client→server, server→DB, server→shell, server→another service, user
  content→rendered HTML).
- **Sinks** — dangerous operations (SQL execution, command execution, HTML
  rendering, file path resolution, redirects, deserialization, auth
  decisions).
- **The auth model** — who can be authenticated, what roles exist, and how
  each protected resource decides whether *this* user may touch *this*
  object.

Write this inventory down as you go. You will reference it constantly, and it
becomes the "Scope" section of the report — it's how the reader knows what you
actually looked at.

### Phase 2 — Run scanners, then hunt manually

**Run the tools first.** For known patterns they are faster and more complete
than reading files, because they parse the AST rather than pattern-matching
text. Your time is better spent proving findings than hunting for obvious ones.

```bash
bash scripts/run_scanners.sh <project-root>
```

This runs whatever is installed — Semgrep, gitleaks, Trivy, Snyk, Bandit,
`npm audit`, `pip-audit` — merges every scanner's SARIF into one normalized
set (so the same issue found by two tools is one finding, not two), and loads
it all into the store as `candidate`.

If Semgrep isn't installed, say so and offer to install it:
`pip install semgrep` — free, offline, no account. It is the single biggest
coverage gap you can close in one command.

**Already have scanner output?** Ingest it directly. Anything that emits SARIF
works — CodeQL, Checkov, ESLint `--format sarif`, commercial scanners:

```bash
python scripts/findings.py ingest existing-results.sarif --label "CI run 412"
```

This is the point of the design: scanme is a proof-and-fix layer on top of
whatever the project already runs, not a competing scanner.

**Then hunt what scanners systematically miss.** IDOR, mass assignment, and
broken tenant isolation are semantic, not syntactic — generic rulesets rarely
catch them, and they are the highest-severity classes in practice. Read
[references/vulnerability-classes.md](references/vulnerability-classes.md) and
work them against your Phase 1 surface map by hand. `find_candidates.sh` gives
a regex starting point but its output is not auto-ingested; read it yourself.

Record anything you find manually into the store so it gets the same tracking
as scanner output.

Everything in the store after this phase is a `candidate` — a lead, not a
finding. Scanners are wrong constantly in both directions. Proof is Phase 3.

### Phase 3 — Prove or discard

This is the phase that makes this skill different. Do not skip it, and do not
soften it when a candidate "obviously" looks real — "obviously" is what
everyone says right before a false positive.

Read [references/verification.md](references/verification.md) for the full
method. In summary, every candidate must reach one of these tiers:

**Tier 1 — Executable reproduction.** You run something (a test, a script, a
`curl`) against a local instance and observe the vulnerability actually
happening: data returned that shouldn't be, a command executing, an auth check
bypassed. Strongest possible evidence. Prefer this whenever the app can be
run.

**Tier 2 — Traced data flow.** When you can't run the app, you prove
reachability on paper: quote the exact source where attacker data enters, every
hop it takes, and the sink it reaches — demonstrating there is no sanitization
or authorization check anywhere along that path. A trace with a gap in it is
not a Tier 2 proof; it's a lead.

**Tier 3 — Unproven.** Everything else. These are **not vulnerabilities** and
must never be presented as such. They go to the appendix as leads, with a note
on what specifically stopped you from confirming (couldn't run the app,
couldn't determine if middleware sanitizes, needs credentials you don't have).

Record every verdict in the store as you reach it, so the reasoning survives
the session:

```bash
# Proven — Tier 1 (reproduced) or Tier 2 (traced source-to-sink)
python scripts/findings.py promote a1b2c3d4 --tier 1 \
  --note "curl as user B returned user A's order 4471"

# Ruled out — the reason is the valuable part
python scripts/findings.py discard e5f6a7b8 \
  --reason "innerHTML fed a hardcoded string literal, not reachable by input"
```

Discarding a candidate is a successful outcome, not wasted effort. A recorded
reason — "input is a hardcoded enum, not attacker-controlled" — stops the next
scan from re-raising it and stops the next person from re-investigating it.

### Phase 4 — Fix, with the test written first

For every Tier 1 / Tier 2 finding you're going to fix, the sequence matters:

1. **Write the regression test first**, encoding the exploit as a test case.
2. **Run it against the unfixed code and watch it fail.** This step is not
   optional and not a formality. A test that passes before you fix anything is
   a broken test — it isn't detecting the vulnerability, and if you'd skipped
   this you'd have shipped a fix "verified" by a test that verifies nothing.
   This is the most common way security fixes silently fail.
3. **Apply the fix.**
4. **Run the test again and watch it pass.**
5. **Run the full existing test suite** to confirm you didn't break behavior
   elsewhere. A security fix that breaks the app gets reverted by the user,
   which means the vulnerability comes back.

Then record it, naming the test that guards it:

```bash
python scripts/findings.py fix a1b2c3d4 --test tests/security/test_order_idor.js
```

The store **refuses** to mark a finding fixed with no test unless you pass
`--force`. That friction is deliberate: a fix whose test never went red is
unverified, and if this fix ever silently reverts, a later scan will flip the
finding to `regressed` and surface it loudly. That only works if `fixed`
honestly means "patched and guarded."

If any step can't be completed — no test framework, can't run the app, the fix
requires a design decision — then **don't fix it**. Report it with a suggested
patch and say why you didn't apply it. An unverified fix is worse than no fix,
because it creates false confidence.

Read [references/fix-and-regress.md](references/fix-and-regress.md) for what to
fix automatically versus what to leave to the user. The short version: fix what
has one correct answer (parameterize a query, escape output, add the missing
ownership check where the ownership model is unambiguous). Leave anything that
requires knowing the product's intent, changes the auth model's design, or
touches cryptography.

### Phase 5 — Report

**First record the scope.** The report grades what you examined, so a grade
without a stated scope is meaningless — this field is what keeps the whole
report honest:

```bash
python scripts/findings.py meta project --set "Acme Storefront"
python scripts/findings.py meta scope --set "Full review of the 14 API routes in src/api/, auth middleware, and the DB layer. Semgrep run with p/security-audit. Findings reproduced against a local instance."
python scripts/findings.py meta not_checked --set "- Frontend bundle
- Infrastructure and TLS configuration
- Third-party payment integration"
```

**Then generate.** The store is the source of truth; hand-copied tables drift:

```bash
python scripts/findings.py scorecard                    # at-a-glance verdict
python scripts/findings.py report > SECURITY_AUDIT.md   # the full report
python scripts/findings.py diff                         # what changed
```

The report gives the user a **before → after grade** (e.g. `D 40/100` →
`A 100/100`), a plain-English explanation of each vulnerability for readers who
are not security engineers, exactly what was done about each one, the test now
guarding it, and a prominent "what this does **not** tell you" section.

Scoring, so you can explain it if asked: start at 100, subtract 30 per proven
critical, 15 high, 6 medium, 2 low. Regressions count 1.5× because someone
already believes they are closed. **Only proven findings move the score** —
unproven candidates never do, or a noisy scanner could tank a grade over things
that are not real.

Show the user the scorecard in chat and tell them where the full report is.

**Lead with regressions if there are any.** A finding that was fixed and came
back is more urgent than a new one of equal severity, because someone already
believed it was closed.

Read [references/reporting.md](references/reporting.md) for the exact format.

Every reported vulnerability carries: severity with justification, the proof
(reproduction steps or the traced flow), the fix applied, and the regression
test that guards it. Findings without proof do not appear in the findings
section — they appear in the appendix, labeled as unverified.

Lead the summary with the count that matters: *proven* vulnerabilities, fixed
versus outstanding. Not "247 issues detected."

## Calibrating severity honestly

Severity is about consequence and reachability, not about which category the
bug falls into. A stored XSS in an admin-only page seen by three people is not
the same as reflected XSS on the login page. An IDOR exposing other users'
billing records is critical; one exposing their public display names is not.

Rank by: what does an attacker get, how hard is it to reach, and how many
users are affected. Say the reasoning out loud in the report. Inflated severity
is the second-most-common way security tooling loses trust, right after false
positives.

## What this skill does not do

Say this plainly in the report rather than letting the user assume otherwise:

- It is a **code audit**, not a penetration test. It does not test running
  infrastructure, network configuration, DNS, TLS setup, or cloud IAM.
- It cannot prove the *absence* of vulnerabilities. "No proven findings" means
  exactly that — not "this app is secure."
- It won't catch business-logic flaws that depend on understanding what the
  product is supposed to do (a discount that can be applied twice, a workflow
  state that can be skipped) unless the user explains the intended behavior.

Overstating coverage is how security tools get people hurt. Be exact about
what was and wasn't examined.
