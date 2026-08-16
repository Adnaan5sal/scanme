# scanme — agent instructions

Works with any AI coding agent that can read a file and run shell commands:
Claude Code, Cursor, Aider, Codex CLI, GitHub Copilot Workspace, Windsurf, or
a generic LLM harness with shell access. Point your agent at this file (or
have it read this repo) and it has everything it needs — the methodology
below plus a set of small, dependency-free Python/Bash scripts in
`scripts/` that any agent can invoke directly.

If you're using **Claude Code** specifically, [SKILL.md](SKILL.md) is a thin
wrapper around this file with the few genuinely Claude-Code-specific pieces
(its `Agent` tool syntax, Browser MCP tool names, the `PreToolUse` hook
mechanism) — read this file either way, that one just adds the glue.

## One system, several modes

Everything below shares two things: the same proof discipline (a finding
does not exist until it's proven — or is explicitly marked as a checklist
item, a lead, or a guideline, never presented as more certain than it is),
and the same finding store and report generator (`scripts/findings.py`), so
a project accumulates *one* coherent audit trail across however many modes
touch it, not a pile of differently-formatted documents that drift apart.

| The request sounds like... | Mode | Detail |
|---|---|---|
| "audit my app", "find vulnerabilities", "is this safe to ship" | **Audit Mode** (below) | The flagship — proof-tiered, fix-with-test, the finding store |
| Building auth/API/payment/upload code right now | **Guard Mode** | [guard-mode.md](references/guard-mode.md) |
| "harden this before I deploy" (fast, not full-audit) | **Guard Mode → fast pass** | same file |
| "compliance audit", "SOC 2 readiness", "launch checklist" | **Compliance Mode** | [compliance-methodology.md](references/compliance-methodology.md) |
| Anything with an LLM: chatbot, RAG, agent, tool-calling | **AI Security Mode** | [ai-threats.md](references/ai-threats.md) |
| "add security headers", CSP, header-scanner grade | **Headers Mode** | [security-headers.md](references/security-headers.md) |
| "write me security tests", standing CI coverage | **Test Generation** | [test-patterns.md](references/test-patterns.md) |
| "production ready", "deploy ready", non-security bug sweep | **Readiness Mode** | [production-readiness.md](references/production-readiness.md) |
| "multi-agent pentest", live/dynamic testing, third-party target, dashboard | **Swarm Mode** | [agent-personas.md](references/agent-personas.md) |

If a request is ambiguous, default to Audit Mode — it's the most rigorous and
the others fold naturally out of it (Guard Mode is Audit Mode's checklist
applied while writing instead of after; Compliance Mode is Audit Mode's
findings mapped onto a formal framework).

---

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

Static review of source code the user hands you is always fine. This applies
across every mode, not just Audit Mode.

---

## Audit Mode — the proof-tiered vulnerability workflow

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
noisy output this methodology exists to avoid. Spend real effort here first.

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
The same classes, written for prevention instead of detection, are in
[guardrails-security.md](references/guardrails-security.md) if you want the
"how to write it correctly" framing while fixing something in Phase 4.

Record anything you find manually into the store so it gets the same tracking
as scanner output.

Everything in the store after this phase is a `candidate` — a lead, not a
finding. Scanners are wrong constantly in both directions. Proof is Phase 3.

### Phase 3 — Prove or discard

This is the phase that makes this methodology different. Do not skip it, and
do not soften it when a candidate "obviously" looks real — "obviously" is
what everyone says right before a false positive.

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
   [test-patterns.md](references/test-patterns.md) has the concrete patterns
   if this is more than a one-off (authorization matrix, auth rules, input
   handling, rate limiting, sessions).
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
python scripts/dashboard.py --root . -o dashboard.html   # self-contained HTML
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

Show the user the scorecard directly and tell them where the full report and
dashboard are.

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

---

## Guard Mode — while code is being written

Full detail in [references/guard-mode.md](references/guard-mode.md). Two
uses: **inline**, applying [guardrails-security.md](references/guardrails-security.md)
and [guardrails-reliability.md](references/guardrails-reliability.md) *as*
code is written (the moment you're about to write
`Model.findById(req.params.id)` with no ownership scoping is the moment to
add the scoping, not a finding for later); and a **fast pass** before
shipping that's quicker but weaker evidence than full Audit Mode, routing its
findings through the same store and the same `scorecard`/`report` output —
there is deliberately one report format, not two.

**Permanent inline coverage, if your tool supports pre-write hooks:**
Claude Code's `PreToolUse` hooks, Cursor's rules, and similar mechanisms in
other agents can all run `scripts/guard.py` on every file write — it's a
small, fast, dependency-free script that reads the code about to be written
and returns guardrail text when a pattern matches, silent otherwise. Wiring
instructions for Claude Code specifically are in
[SKILL.md](SKILL.md#guard-mode-hook); other tools should point their
equivalent hook mechanism at `scripts/guard.py` the same way. Without a hook,
apply the checklist manually while writing — Guard Mode still works, it's
just not automatic.

## Compliance Mode — formal 35-section audit

Full detail across
[compliance-methodology.md](references/compliance-methodology.md) (sampling
strategy, evidence standards, materiality thresholds — what separates this
from a checklist),
[compliance-checklist-core.md](references/compliance-checklist-core.md)
(§1–15: governance, architecture, auth, authz, sessions, input, injection,
XSS, CSRF, API, database, secrets, uploads, frontend, headers),
[compliance-checklist-operations.md](references/compliance-checklist-operations.md)
(§16–28: CORS, dependencies, infrastructure, CDN/WAF, logging, monitoring,
error handling, backups, availability, CI/CD, security testing, vulnerability
management, incident response), and
[compliance-checklist-specialized.md](references/compliance-checklist-specialized.md)
(§29–35: privacy, third-party, payment, AI/LLM, admin, compliance
documentation, the final production gate).

Every item is tagged **[code]** (verify by reading source — do this),
**[confirm]** (ask the user — infrastructure, process, backups-actually-
tested; group these into one set of questions), or **[specialist]**
(compliance/legal/PCI-QSA territory — flag it, don't improvise it). Read
[priorities.md](references/priorities.md) for the reference architecture
diagram and the "10 things to never skip" list to lead the report's summary
with what actually matters most, before the full 35-section detail.

Findings from Compliance Mode go through the same finding store as Audit
Mode — a §4 authorization gap found here and one found by a full Audit Mode
pass are the same kind of finding, tracked the same way, appearing in the
same report.

## AI Security Mode — LLM-specific threats

Full detail in [ai-threats.md](references/ai-threats.md): indirect prompt
injection, RAG authorization and tenant isolation, agent/tool privilege,
output handling, cost/abuse controls, data privacy. Only applicable when the
app calls an LLM.

The one thing to hold onto: **a system prompt is a request, not a security
boundary.** "The system prompt says not to reveal other users' data" can be
argued with by an attacker; a query filter cannot. Fixes here are
architectural (a missing tenant filter, an unvalidated tool argument, a
missing spending cap) not prompt-level ("please don't reveal secrets" added
to the system prompt is defense in depth at best, never *the* fix).

Prompt-injection resistance is probabilistic, unlike SQL injection — "I tried
three injections and they didn't work" is not evidence of safety. What's
provable is containment: whether a successful injection could reach anything
consequential. Same Tier 1/2/3 proof discipline as everywhere else in this
methodology.

## Headers Mode — CSP and security headers

Full detail in [security-headers.md](references/security-headers.md):
inventory what the app actually loads (static + runtime) before writing a
policy, deploy `Content-Security-Policy-Report-Only` before enforcing, verify
headers are on the *actual response* not just the config file. A generic
copy-paste CSP either breaks the site or does nothing — the useful policy can
only be derived from what this specific app loads.

## Test Generation — widening coverage beyond one fix

Phase 4 above writes one test per proven finding. When the ask is bigger —
"write me security tests", "how do I stop this class of bug coming back" —
read [test-patterns.md](references/test-patterns.md) for the authorization
matrix pattern (the single highest-value thing to generate, since broken
access control is both the most common serious vulnerability and the one
most likely to be silently reintroduced by ordinary feature work), plus
authentication, input-handling, rate-limit, and session test patterns.

Same verification discipline applies: a test that has never gone red is not
known to detect anything. Temporarily break the code the test is supposed to
guard, confirm the test fails, restore the code, confirm it passes.

## Readiness Mode — beyond security

Full detail in
[production-readiness.md](references/production-readiness.md): error
handling, code quality, performance, deploy/config readiness, accessibility,
dependency health. This is what "make this production ready" or "check my
app before I deploy" usually means beyond the security surface —
`scan_common_issues.sh` gives a fast first pass, same discipline as
everywhere else: every hit is a lead to verify, not a finding.

Security findings surfaced during a readiness pass route through Audit Mode
(they need proof and a regression test, not a quick patch) — don't
re-derive vulnerability findings here that belong in the main workflow.

## Swarm Mode — autonomous multi-agent testing

Full detail in [agent-personas.md](references/agent-personas.md) and
[live-testing.md](references/live-testing.md). The heavier counterpart to
Audit Mode: parallel specialist subagents (recon → injection-hunter,
auth-hunter, client-side agents in parallel → chain-hypothesis), sandboxed
exploit execution (`scripts/sandbox_exec.sh` — real Docker isolation when
installed, a resource-limited fallback that says loudly it is *not*
isolation when it isn't), live/dynamic testing including real browser-based
XSS/CSRF testing, and an HTML dashboard.

**Dispatching the parallel agents** depends on what your tool supports: if
it has a sub-task/sub-agent capability (Claude Code's `Agent` tool, similar
mechanisms in other agent frameworks), spawn the Injection-hunter,
Auth-hunter, and Client-side personas concurrently. If it doesn't, work
through the personas from [agent-personas.md](references/agent-personas.md)
sequentially in the same session — the proof discipline and the shared
ledger are what actually make this work, the concurrency is a speed
optimization on top, not a requirement for correctness.

**Browser-based testing** (the Client-side persona) needs whatever browser
automation your agent has access to — Playwright MCP, Puppeteer MCP, Claude
Code's Browser tools, or a similar built-in capability. See
[live-testing.md](references/live-testing.md) for the concrete methodology
(safe self-checking payloads, what to inspect) independent of which specific
tool executes it.

**Authorization gate, mandatory before any live-target phase:**

```bash
python scripts/authorize.py record --target <url> --scope owner --by "..."
# or, for a target the user doesn't own outright but has permission for:
python scripts/authorize.py record --target <url> --scope third-party \
  --by "Acme Corp" --note "Bug bounty, scope *.acme.com, ref BB-2026-114"
python scripts/authorize.py check --target <url>   # gates every phase after
```

Third-party authorization requires the `--note` — a bare confirmation is not
enough at that tier. This is on top of the standing Scope and authorization
rule above, made mechanical here rather than left to memory, because Swarm
Mode is the mode most likely to actually touch a live target.

Findings from every agent go through the same store as every other mode —
tag the `tool` field with the agent's name (`auth-hunter agent`, not just
`scanme`) so `scripts/dashboard.py`'s dashboard shows genuine provenance.

**Auto-fix as a PR**, gated behind explicit confirmation (pushing and
opening PRs are effectful actions, never silently automated):

```bash
bash scripts/auto_pr.sh <fingerprint>              # prints commands, stops
CONFIRM=yes bash scripts/auto_pr.sh <fingerprint>   # actually pushes + opens PR
```

Say plainly where this is lighter than a full platform: multi-agent
coordination here is through the shared ledger, not live message-passing
between running agents; the Docker fallback is resource-bounded, not
isolated; there is no full HTTP traffic interception (recommend Burp/Caido
for that). Don't let the "swarm" name imply more sophistication than what's
actually running.

---

## What this methodology does not do

Say this plainly in reports rather than letting the user assume otherwise:

- It is a **code audit**, not a penetration test. It does not test running
  infrastructure, network configuration, DNS, TLS setup, or cloud IAM —
  those are [confirm]/[specialist] items in Compliance Mode, not something
  any mode here can verify from source.
- It cannot prove the *absence* of vulnerabilities. "No proven findings" means
  exactly that — not "this app is secure." A clean grade describes what was
  examined and nothing else.
- It won't catch business-logic flaws that depend on understanding what the
  product is supposed to do (a discount that can be applied twice, a workflow
  state that can be skipped) unless the user explains the intended behavior.
- Guard Mode and the fast pass reduce the *rate* of common, well-understood
  mistakes getting written — they do not make an application invulnerable,
  and never say or imply that.
- Prompt-injection resistance in AI Security Mode is never provable by
  testing, only architectural containment is.
- Compliance Mode produces internal working documentation that prepares for
  a formal certification (SOC 2, ISO 27001, PCI DSS) — it does not
  substitute for one, and does not draft legal/compliance language.

Overstating coverage is how security tools get people hurt. Be exact about
what was and wasn't examined, in every mode.

## Demo

[demo/README.md](demo/README.md) walks through Audit Mode end to end against
a real vulnerable API — two criticals a 225-rule Semgrep scan misses
entirely, both exploited over HTTP, fixed with test-first regression
coverage, and a simulated regression caught precisely by the finding store.
`bash demo/vulnshop/run_demo.sh` reproduces it in about 20 seconds, no
install required — works the same regardless of which agent runs it, since
it's plain Node/Python scripts underneath.
