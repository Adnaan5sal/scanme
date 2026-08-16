# Contributing to scanme

The most useful contribution right now isn't code — it's running scanme
against something real and reporting back what happened, especially if you
found a place where the proof model breaks down.

## What's most valuable

**1. Run it against a project you own (or have explicit permission to test)
and open an issue with the result** — whether it worked, whether a finding
was wrong, whether a proof tier claim didn't hold up. See
[Scope and authorization](AGENTS.md#scope-and-authorization) — never point
this at something you don't have clear permission to test.

**2. Try it in an agent other than Claude Code** (Cursor, Codex CLI, Aider,
Copilot Workspace, Cline, anything else that reads `AGENTS.md` and runs
shell commands) and report whether it worked, and what — if anything — had
to be adapted. The Supported agents table in the README only has
checkmarks for what's actually been verified; this is how it gets more.

**3. Point out a false positive or a false negative.** If scanme calls
something Tier 1 or Tier 2 proven and the proof doesn't hold up, that's the
single most damaging kind of bug this project can have — see
[references/doctrine.md](references/doctrine.md) principle 1 for why. Open
an issue with the specific finding and what's wrong with the proof.

**4. Code contributions** — new vulnerability-class checks, scanner
integrations (anything that emits SARIF), fixes to the scripts in
`scripts/`. Keep the existing discipline: no finding without a proof tier,
no fix without a regression test that was confirmed failing first.

## Before opening a PR

- **Run the demo** (`bash demo/vulnshop/run_demo.sh`) and confirm it still
  passes (8/8 tests) — this is the fastest smoke test for "did I break
  something in the core pipeline."
- **If you're touching a script**, run it directly and check the exit code
  and output make sense, not just that it doesn't crash.
- **If you're adding a vulnerability class or a mode**, it needs the same
  proof-tier discipline as everything else — see the "Prove or discard"
  phase in [AGENTS.md](AGENTS.md). A mode that reports unproven findings
  as findings doesn't get merged; that's the one thing this project can't
  compromise on.
- **Keep scripts dependency-free** (Python stdlib, Bash) unless there's a
  strong reason not to — part of what makes this agent-agnostic is that any
  agent can run the scripts without an install step.

## Reporting a security issue in scanme itself

If you find a vulnerability in scanme's own scripts (not in something
scanme audits — in scanme itself), please use the security issue template
when opening an issue rather than a general bug report, so it gets
triaged with the right urgency.

## Code of conduct

Be direct about disagreement — this project's entire premise is that
overclaiming in security tooling is actively harmful, so "I don't think
this proof holds up" is exactly the kind of feedback that's welcome, not
unwelcome. Just keep it about the work.
