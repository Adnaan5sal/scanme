# Agent personas — the "graph of agents" pattern

Strix's core idea is specialist agents working in parallel and sharing
discoveries so they can chain vulnerabilities together (a leaked internal
path from one agent becomes the SSRF target for another). This is
implemented here using the Agent tool to spawn real, independent subagents
against the same target, each with a narrow brief, all writing into the
**same finding store** so their discoveries compose.

## Why parallel specialists instead of one linear pass

A single model working phase-by-phase (scanme's Audit Mode) is thorough but
serial — auth review happens, then injection review happens, then chaining
happens, one after another. A specialist agent per class can work
simultaneously, and more importantly, a narrow brief produces a sharper agent
than a general "find all the bugs" prompt: an agent told *only* to hunt
authorization gaps reads every handler looking for exactly one shape of
mistake, rather than skimming everything for whatever looks interesting.

## The five personas

Spawn these as parallel `Agent` tool calls (same message, multiple
invocations) against the same target. Each gets the attack-surface map from
Phase 1 as shared context, plus its own narrow brief.

### 1. Recon agent

**Brief:** Map the target exhaustively before anyone else starts hunting.
Enumerate every route/endpoint, every input source (query params, body
fields, headers, cookies), the auth model (how tokens are issued, what roles
exist), the data model (which resources have owners), and every third-party
integration. Output: a structured surface map, not findings. This agent's
output becomes the shared context every other agent starts from — it runs
first and alone, not in parallel with the others.

### 2. Injection-hunter agent

**Brief:** Given the surface map, hunt SQL/NoSQL/command/template/path
injection. For each candidate sink, trace whether attacker-controlled input
reaches it unsanitized. Attempt Tier 1 reproduction with safe payloads
(`SLEEP(5)` not `DROP TABLE`, marker files to a scratch directory not
production paths) run through `scripts/sandbox_exec.sh`. Record every
verdict — proven, discarded, or unproven — in the finding store, tagged with
this agent's name as the `tool` field so provenance is visible in the
dashboard.

### 3. Auth-hunter agent

**Brief:** Hunt broken authentication and authorization: IDOR, privilege
escalation, JWT weaknesses (`alg: none`, unverified signatures), session
fixation, missing ownership checks. This is historically the highest-yield
persona — broken access control is the most common serious web vulnerability
and the easiest for a narrow, patient agent to find, because it requires
methodically checking *every* resource-by-ID endpoint against *every* actor,
which a generalist agent skims past.

### 4. Client-side agent

**Brief:** Uses the Browser tools (`mcp__Claude_Browser__*`) to test what
static analysis can't reach: reflected/DOM XSS actually firing in a real
browser, CSRF via observing cross-origin requests, clickjacking via iframe
embedding, CSP bypass attempts, and reading actual network requests
(`read_network_requests`) to find secrets or excessive data exposure in API
responses the frontend never renders. This is the one persona that requires
a live, running target — it cannot work from source alone. **This is the
capability scanme's Audit Mode structurally lacks** — real browser-based
dynamic testing.

### 5. Chain-hypothesis agent

**Brief:** Runs *after* the other four report their proven findings, not in
parallel with them. Reads every proven finding from the store
(`python scripts/findings.py list --status proven`) and asks: does any
combination of these compose into something worse than the sum of its
parts? (A low-severity information leak from the recon agent plus an SSRF
finding from the injection-hunter might together reach the cloud metadata
endpoint and extract credentials — neither alone was critical, but chained,
it is.) This is Strix's "agents share discoveries and chain vulnerabilities"
idea, implemented as a dedicated pass over already-proven findings rather
than as implicit coordination between running agents — deliberately simpler
and more auditable: every chain hypothesis is either proven at Tier 1/2 like
any other finding, or discarded with a reason, same as everything else in
this skill.

## Dispatch pattern

```
Phase 1: spawn Recon agent alone, wait for the surface map
Phase 2: spawn Injection-hunter, Auth-hunter, Client-side agents in parallel
         (same message, three Agent tool calls), each given the surface map
Phase 3: once all three report, spawn Chain-hypothesis agent alone
Phase 4: fix + regression-test proven findings (same discipline as Audit Mode)
Phase 5: dashboard.py + findings.py report
```

Give each spawned agent explicit instructions to use `findings.py` to record
what it finds — `promote`/`discard` with a `--note` explaining the proof,
and to name itself in any manual record it creates (e.g. `tool: "auth-hunter
agent"`) so the dashboard's "source/agent" column is meaningful, not just
"scanme"/"swarm" for everything.

## Honesty about what this is and isn't

This is **not** the same engineering as Strix's persistent, always-on agent
swarm with a shared long-running session and live coordination mid-task. It
is four to five independent, short-lived subagent invocations that read and
write a shared SQLite store as their coordination mechanism — coordination
by shared state, not by live message-passing between running agents. That's
a real difference in sophistication. What it does capture genuinely: real
parallelism (agents run concurrently, not simulated), real narrow-brief
specialization (each agent is measurably better at its one job than a
generalist would be), and real chaining (the chain-hypothesis pass reads
actual proven findings, not fabricated ones).
